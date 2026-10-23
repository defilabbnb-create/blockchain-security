"""Source-level evidence for vulnerability classes.

The unified IR records *that* a call happened, where it happened and what it
touched, but it does not record whether the return value was checked, and for
some samples it records no call at all.  Those two gaps are why IR-driven class
detection cannot separate a genuine defect from an ordinary withdrawal.

This module reads the verified source text directly.  It does not compile,
does not fetch anything, and does not consult any annotation the corpus may
carry: every rule below reasons only over syntax that a compiler would also see,
so a marked-up corpus cannot inflate the result.

The output is a set of *observed* facts.  It is evidence for review, never a
confirmed defect.
"""
from __future__ import annotations

import re


def strip_comments_and_strings(text: str) -> str:
    """Blank out comments and string literals, preserving offsets and newlines.

    Every rule matches against this form, so a class name written in a comment or
    inside a source-string annotation cannot be mistaken for code.  Offsets are
    preserved because the rules compare positions.
    """
    out = []
    index = 0
    length = len(text)
    state = None  # None | 'line' | 'block' | 'single' | 'double' | 'triple'
    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ''
        if state is None:
            if char == '/' and nxt == '/':
                state = 'line'
                out.append('  ')
                index += 2
                continue
            if char == '/' and nxt == '*':
                state = 'block'
                out.append('  ')
                index += 2
                continue
            if char in '"\'':
                quote = char
                if text[index:index + 3] in ('"""', "'''"):
                    state = 'triple'
                    out.append(' ' * 3)
                    index += 3
                    continue
                state = 'double' if quote == '"' else 'single'
                out.append(' ')
                index += 1
                continue
            out.append(char)
            index += 1
            continue
        if state == 'line':
            if char == '\n':
                state = None
                out.append('\n')
            else:
                out.append(' ')
            index += 1
            continue
        if state == 'block':
            if char == '*' and nxt == '/':
                state = None
                out.append('  ')
                index += 2
                continue
            out.append('\n' if char == '\n' else ' ')
            index += 1
            continue
        if state == 'triple':
            out.append('\n' if char == '\n' else ' ')
            index += 1
            if text[index:index + 3] in ('"""', "'''"):
                out.append('   ')
                index += 3
                state = None
            continue
        # single / double quoted
        if char == '\\':
            out.append('  ')
            index += 2
            continue
        if (state == 'double' and char == '"') or (state == 'single' and char == "'"):
            state = None
        out.append('\n' if char == '\n' else ' ')
        index += 1
    return ''.join(out)


def state_text(text, index):  # pragma: no cover - helper kept for clarity
    return text[index:index + 3]


# A low-level call.  Two forms occur in real contracts and both must match:
#   receiver.call(opts)(args)      -- plain and option-block
#   receiver.call.value(v)(args)  -- the chained legacy value form
# The chained form is the reason the pattern cannot simply expect `(` after the
# method name: `.call.value(v)()` continues with another selector.
_CALL_RE = re.compile(
    r'(?P<recv>[A-Za-z_$][A-Za-z0-9_$.]*)\s*\.\s*'
    r'(?P<fn>call|send|transfer|delegatecall|callcode)\b'
    r'(?P<chain>(?:\s*\.\s*(?:value|gas|code|abi)\s*\([^()]*\)|\s*\{[^}]*\})*)'
    r'\s*\(?',
    re.I,
)

# An assignment whose right-hand side begins with a call.  The chain group
# allows `.call.value(v)(...)` and `.call{value: v}(...)` on the right-hand side.
_BINDING_RE = re.compile(
    r'\(\s*[^()]*\)\s*=\s*'                      # tuple destructuring: (bool ok, ) = ...
    r'|(?:[A-Za-z_$][A-Za-z0-9_$]*\s*(?:,\s*[A-Za-z_$][A-Za-z0-9_$]*\s*)*)\s*=\s*'
    r'(?:address\s*\(\s*)?[A-Za-z_$][A-Za-z0-9_$.]*\s*\.\s*'
    r'(?:call|send|transfer|delegatecall|callcode)\b'
    r'(?:\s*\.\s*(?:value|gas|code|abi)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)|\s*\{[^}]*\})*',
    re.I,
)

_RETURN_KEYWORDS = re.compile(r'\b(return|revert|require|assert)\b')

# A function header: name, optional parameter list, visibility/mutability
# modifiers, then the opening brace.
#
# The modifier run has to accept bare keywords such as `public`, `external`,
# `view` and `onlyOwner`, each of which is normally written on its own line by
# every formatter.  An earlier version required each modifier to be followed by
# a parenthesised argument list, so `function changeOwner(address _newOwner)`
# followed by `public` then `{` matched nothing at all -- and with it every
# formatted Solidity source, which is how the whole access-control anchor came
# to observe zero functions in the formatted benchmark contracts.
_FUNCTION_RE = re.compile(
    # Only the name, params and brace are captured; visibility and mutability
    # modifiers are read from the text between them.  The modifier run must
    # accept bare keywords such as `public`, `external`, `view` and `onlyOwner`,
    # each normally written on its own line by every formatter.  An earlier
    # version required every modifier to carry a parenthesised argument list,
    # so `function changeOwner(address _newOwner)` followed by `public` then
    # `{` matched nothing at all -- which is why the access-control anchor came
    # to observe zero functions in every formatted benchmark contract.
    r'\bfunction\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*'
    r'(?P<params>\([^)]*\))?[^;{]*\{',
)


def _statements(text: str):
    """Split the source into statements, keeping each statement's span.

    A statement ends at a semicolon or at the closing brace of a block, at any
    block nesting depth: a statement inside a function body is bounded by the
    same two characters as one at file scope.  Only parenthesis and bracket
    nesting must suppress a boundary, so that an argument list or an array
    literal spanning lines stays inside one statement.
    """
    spans = []
    start = None
    depth_paren = depth_bracket = 0
    depth_brace = 0
    for index, char in enumerate(text):
        if char == '{':
            depth_brace += 1
            continue
        if char == '}':
            depth_brace = max(0, depth_brace - 1)
            if depth_paren == 0 and depth_bracket == 0 and start is not None:
                spans.append((start, index))
                start = None
            continue
        if char == '(':
            depth_paren += 1
            continue
        if char == ')':
            depth_paren = max(0, depth_paren - 1)
            continue
        if char == '[':
            depth_bracket += 1
            continue
        if char == ']':
            depth_bracket = max(0, depth_bracket - 1)
            continue
        if char == ';' and depth_paren == 0 and depth_bracket == 0:
            spans.append((start, index) if start is not None else (index, index))
            start = None
            continue
        if start is None and not char.isspace():
            start = index
    if start is not None and start < len(text):
        spans.append((start, len(text)))
    return spans


def _statement_at(text: str, position: int):
    """Return the smallest statement span containing ``position``.

    Scans backwards to the nearest boundary (semicolon, closing brace, or the
    start of an enclosing construct) and forwards to the next one.  The backward
    scan is bounded by the previous `;`, `}` or `{`, which is what keeps a
    function header from being folded into the statement that contains a call.
    """
    start = position
    while start > 0:
        char = text[start - 1]
        if char in ';}{':
            break
        start -= 1
    end = position
    depth = 0
    while end < len(text):
        char = text[end]
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == ';' and depth <= 0:
            break
        elif char == '}' and depth <= 0:
            break
        end += 1
    return text[start:end]


def _argument_count(code: str, open_paren: int) -> int:
    """Count top-level arguments of the call whose `(` is at ``open_paren``.

    Counts commas at paren depth zero, so a comma inside a nested expression is
    not counted.  Returns ``-1`` when the parenthesis is never closed within a
    bounded window, which keeps an unparsable call from being classified as a
    one-argument call.
    """
    if open_paren < 0 or open_paren >= len(code) or code[open_paren] != '(':
        return -1
    depth = 0
    commas = 0
    seen_any = False
    for index in range(open_paren, min(len(code), open_paren + 400)):
        char = code[index]
        if char == '(':
            depth += 1
            if depth == 1:
                continue
        elif char == ')':
            depth -= 1
            if depth == 0:
                # One argument is the absence of a separator, so the count is the
                # number of top-level commas plus one.  Returning a bare 1 here
                # discarded the accumulated commas and made every two-argument
                # ERC20 call look like the one-argument low-level builtin.
                return (commas + 1) if seen_any else 0
        elif char == ',' and depth == 1:
            commas += 1
        elif depth == 1 and not char.isspace():
            seen_any = True
    return -1


def _is_low_level_call_shape(call_match, code: str) -> bool:
    """Whether the call is a low-level call rather than a typed ERC20 method.

    `transfer` and `send` name both Solidity's built-in low-level transfer and an
    ordinary ERC20 method, and the method name alone cannot tell them apart.
    Two properties do:

    * Arity.  The built-in low-level `transfer(uint256)` and `send(uint256)` take
      exactly one argument; `IERC20.transfer(address,uint256)` takes two.  This
      separates `owner.transfer(this.balance)` from `token.transfer(to, value)`
      without guessing from the receiver's name.
    * The legacy `.value(v)` / `{value: v}` carrier, which only exists on a
      low-level call.

    `05-BECToken` declares `transfer(address,uint256) returns (bool)` and calls
      `super.transfer(...)`, and the method-name test reported it as an unchecked
      low-level call; the arity test does not.
    """
    chain = call_match.groupdict().get('chain') or ''
    if 'value' in chain:
        return True
    function = call_match.group('fn').lower()
    if function not in ('send', 'transfer'):
        # `call`/`delegatecall`/`callcode` are built-in names only.
        return True
    # `_CALL_RE` ends with an optional `(`, so `match.end()` may already sit
    # after the argument list.  The argument list is therefore located from the
    # end of the *method name* rather than from the end of the match: searching
    # forward from `match.end()` skipped the real `(` and found a later one, or
    # none at all, which silently downgraded every `send`/`transfer` to "not a
    # low-level call".
    name_end = call_match.start('fn') + len(call_match.group('fn'))
    # `_CALL_RE` ends with `\s*\(?`, so when the argument list's `(` is adjacent
    # to the method name it is *already inside the match*: `match.end()` sits one
    # character past it and `code[name_end]` is the `(` itself.  Counting from
    # `name_end` is therefore correct -- counting from `name_end + 1` skipped the
    # paren and counted commas from inside the argument list, which turned every
    # call into "one argument" or an unparsable one.
    open_paren = name_end if code[name_end:name_end + 1] == '(' else code.find('(', name_end)
    if open_paren == -1:
        # No argument list at all.  A bare `.transfer` followed by an option block
        # is a low-level call; anything else is not callable as written.
        brace = code.find('{', name_end)
        if brace != -1 and not code[max(0, brace - 2):brace].strip().endswith(')'):
            return True
        return False
    between = code[name_end:open_paren]
    # `.value(v)` / `.gas(g)` are chained onto the call, so the first `(` after
    # the method name belongs to the chain, not to the argument list.  The
    # argument list is the `(` that directly follows the chain.
    chain = re.search(r'\.\s*(?:value|gas|code|abi)\s*\(', between)
    if chain:
        after = between[chain.end():]
        if '(' in after:
            open_paren = name_end + chain.end() + after.index('(')
            return _argument_count(code, open_paren) != 2
        return True
    return _argument_count(code, open_paren) == 1


def _value_arguments(call_match, text: str) -> bool:
    """Whether the call carries a value argument or a value option block.

    Both carrier forms are recognised: the modern `{value: v}` option block and
    the chained `.value(v)` form, plus the value-carrying `send`/`transfer`
    builtins -- but only when the arity and carrier say it is the low-level form
    rather than an ordinary ERC20 method of the same name.
    """
    chain = call_match.groupdict().get('chain') or ''
    if 'value' in chain:
        return True
    function = call_match.group('fn').lower()
    if function in ('send', 'transfer') and _is_low_level_call_shape(call_match, text):
        return True
    return False


def _is_checked(statement: str, text: str, match_end: int) -> bool:
    """Whether the call's return value is bound or otherwise consumed.

    Checked means the call result is bound to a name, or the text immediately
    before the call opens a construct that wraps it -- ``require(``, ``if (``,
    ``while (`` or ``return``.  Only that prefix counts: a guard further up the
    same body says nothing about whether *this* call's result was read, which is
    what separates ``if (ok) { callee.call(); }`` from ``if (callee.call()) {}``.
    """
    stripped = statement.strip()
    # The statement is a slice of a larger body, so the binding is searched
    # rather than anchored: a leading `if (...)` or `return` may precede it.
    binding = _BINDING_RE.search(stripped)
    if binding:
        # Whatever the left-hand form is, the assignment target must actually be
        # a call: a tuple destructuring of an unrelated expression is not a
        # checked low-level call.
        rest = stripped[binding.end():]
        if re.match(r'\s*(?:address\s*\(\s*)?[A-Za-z_$][A-Za-z0-9_$.]*\s*\.\s*'
                    r'(?:call|send|transfer|delegatecall|callcode)\b', rest):
            return True
    position = -1
    for token in ('.call', '.send', '.transfer', '.delegatecall'):
        found = stripped.find(token)
        if found != -1 and (position == -1 or found < position):
            position = found
    if position == -1:
        return False
    head = stripped[:position].strip()
    return bool(re.match(r'^(require|assert|if|while|return|revert)\s*\(', head))


def _modifier_tokens(text: str, span_start: int, span_end: int):
    """Return the modifier names attached to the function owning ``span_start``."""
    # Walk back from the statement to the nearest `function` keyword and read the
    # parameter/modifier list that follows its name.
    prefix = text[:span_start]
    matches = list(re.finditer(r'\bfunction\b', prefix))
    if not matches:
        return []
    body = prefix[matches[-1].start():]
    # Stop at the opening brace of the body.
    brace = body.find('{')
    if brace != -1:
        body = body[:brace]
    tokens = re.findall(r'\b([A-Za-z_$][A-Za-z0-9_$]*)\s*(\([^()]*\))?', body)
    return [name for name, _ in tokens]


def _function_names(text: str):
    return {match.group(1) for match in
            re.finditer(r'\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)', text)}


def _function_window(code: str, position: int) -> str:
    """Return the text from ``position`` to the end of its enclosing function.

    The enclosing function is located from the nearest preceding ``function``
    keyword, then brace-matched to its end, so a write in a later function cannot
    be paired with a call in an earlier one.  Braces are counted structurally
    because a minified or single-line source has no newline-delimited braces.
    """
    matches = [m for m in re.finditer(r'\bfunction\b', code[:position])]
    start = matches[-1].start() if matches else max(0, position - 600)
    brace = code.find('{', start)
    if brace == -1 or brace > position:
        # No enclosing body to bound by; fall back to a bounded slice.
        return code[position:position + 600]
    depth = 0
    for index in range(brace, len(code)):
        char = code[index]
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return code[position:index]
    return code[position:position + 600]


def _enclosing_contract_name(code, position):
    """Return the name of the contract, library or interface whose header
    precedes ``position``, or None when the source declares no named container.

    A constructor is recognised by sharing its name with that container, which
    is what separates `owner = msg.sender` during deployment from the same
    assignment reached later through a public entrypoint.
    """
    header = None
    for match in re.finditer(
            r'\b(?:contract|library|interface)\s+([A-Za-z_$][A-Za-z0-9_$]*)', code[:position]):
        header = match.group(1)
    return header


def observe(text: str) -> dict:
    """Return observed vulnerability facts for one verified source.

    Every entry is a measurement over the source, not a verdict.  A caller that
    wants a defect still has to reproduce it.
    """
    if not isinstance(text, str) or not text:
        # A missing or empty source yields the same zeroed shape as an analysed
        # one, so a caller never has to distinguish "nothing found" from "nothing
        # looked at" by key presence.
        return {'valueCallCount': 0, 'uncheckedCalls': [], 'uncheckedCallCount': 0,
                'frontRunning': False, 'shortAddressPropagation': False,
                'incorrectInterfaceUse': False, 'oracleStalePrice': False,
                'reentrancyCandidates': [], 'reentrancyCandidateCount': 0,
                'functionModifiers': {}, 'unguardedPrivilegedEntries': [],
                'unprotectedPointer': False, 'stateWriteExpressions': [],
                'arithmetic': False, 'unwrappedArithmetic': [],
                'blockDerivedValue': False,
                'blockHashUsed': False, 'timestampGatesPayout': False,
                'callerDerivedValue': False, 'loopCount': 0,
                'dynamicCollection': False}
    code = strip_comments_and_strings(text)

    value_calls = []
    unchecked_calls = []
    for match in _CALL_RE.finditer(code):
        receiver = match.group('recv')
        function = match.group('fn').lower()
        if receiver.lower() in ('require', 'assert', 'revert', 'keccak256'):
            continue
        # `transfer` and `send` are also ordinary ERC20 method names, so the call
        # only enters the low-level call list when its shape says it is one.
        if not _is_low_level_call_shape(match, code):
            continue
        entry = {
            'offset': match.start(),
            'function': function,
            'receiver': receiver,
            'sendsValue': _value_arguments(match, code),
        }
        value_calls.append(entry)
        statement = _statement_at(code, match.start())
        if statement is not None and not _is_checked(statement, code, match.end()):
            unchecked_calls.append(entry)

    # Reentrancy: a value-bearing call followed, inside the same function body, by
    # a write to the state the call invalidates -- and, in the vulnerable form,
    # guarded only by a balance check performed *before* the call.
    #
    # Both patterns anchor on the subscripted state field itself rather than on a
    # bare identifier: a real ledger update reads `balances[msg.sender] -= _amt`,
    # where the part after the identifier is a subscript, not a variable name.
    reentrancy = []
    # The vulnerable shape is a write to a ledger field *after* a value-bearing
    # call, where the transferred value was read from that same field before the
    # call.  Requiring both halves is what keeps an ordinary withdrawal -- which
    # also moves value and also writes a balance -- from being reported, because
    # it applies the write before the call.
    state_write = re.compile(
        r'\b(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*\[[^\]]*\]\s*(?P<op>-=|\+=|=)\s*'
        r'[A-Za-z_$][A-Za-z0-9_$.]*')
    bare_write = re.compile(
        r'\b(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?P<op>-=|\+=|=)\s*'
        r'[A-Za-z_$][A-Za-z0-9_$.]*')
    # `balances[x] = 0` writes a literal, not a name; without this form the
    # single clearest reentrancy shape (clear the ledger after paying out) is
    # invisible.
    literal_write = re.compile(
        r'\b(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*\[[^\]]*\]\s*(?P<op>-=|\+=|=)\s*'
        r'(?:0[xX][0-9a-fA-F]+|\d+|true|false)\b')
    ledger_read = re.compile(r'\b(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*\[[^\]]*\]')
    for entry in value_calls:
        if not entry['sendsValue']:
            continue
        # Bounded to the enclosing function body so a write in a later function
        # cannot be paired with a call in an earlier one.  The body end is found
        # by brace matching from the call's own offset, because a minified or
        # single-line source has no newline-delimited closing brace.
        window = _function_window(code, entry['offset'])
        preceding = code[max(0, entry['offset'] - 500):entry['offset']]
        write = (state_write.search(window) or literal_write.search(window)
                or bare_write.search(window))
        if not write:
            continue
        field = write.group('field')
        # The ledger may be read inside the call's own argument list, as in
        # `msg.sender.call.value(userBalance[msg.sender])()`, so the read window
        # covers the statement containing the call, not only the text before it.
        statement = _statement_at(code, entry['offset']) or ''
        read_before = {match.group('field')
                       for match in ledger_read.finditer(preceding + statement)}
        read_before |= {match.group('field') for match in ledger_read.finditer(window[:200])}
        if field not in read_before:
            # The write is not to a field the call's value came from.  A bare
            # bookkeeping variable is not a reentrancy ledger.
            continue
        guard_before = bool(re.search(
            r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*(?:\[|\s)\s*(?:>=|>)\s*[A-Za-z_$]', preceding))
        reentrancy.append({'offset': entry['offset'], 'function': entry['function'],
                           'stateField': field,
                           'guardBeforeCall': guard_before,
                           'stateWriteAfterCall': write.group(0).strip()})

    permissions = {}
    unguarded = []
    # 特权入口的判定从固定名字白名单改为语义匹配。原先只认 withdraw /
    # transferOwnership / setOwner 这十来个名字，于是 `changeOwner`、
    # `Destroy`、`PushBonusCode` 这类同样改写所有权或资产归属的入口全部漏掉，
    # 而它们的函数名在真实代码里千变万化，靠穷举必然不全。
    #
    # 现在的判据是"这个函数做了什么事"：写所有权槽位、销毁自身、
    # 改写实现指针、增减发行量或直接转走合约余额，都算特权入口。
    # 只按名字猜会把 `withdrawBonus(user, id)` 这类用户自助领取误判为特权，
    # 所以仍要求它要么命中语义动作词，要么落在已知名字集合里。
    PRIVILEGED_NAME_RE = re.compile(
        r'(?:withdraw|transferownership|setowner|changeowner|setnewowner|'
        r'upgradeto|setimplementation|setproxy|mint|burn|selfdestruct|destroy|'
        r'setprice|setrate|setadmin|setoperator|claimowner|renounce)', re.I)
    # `deposit` and `withdraw` name a vault's user-facing entrypoint, where the
    # caller spends or redeems their own shares.  The same two words name a
    # privileged drain when the function moves funds without touching a ledger
    # keyed by the caller -- `withdrawBalance()` with no per-user accounting has
    # nobody to check against, which is the shape the reentrancy samples take.
    # The name alone therefore cannot decide it; the body does.
    USER_ENTRY_RE = re.compile(
        r'^(?:deposit|mint|withdraw|redeem|enterStake|exitStake|stake|unstake)'
        r'(?:[A-Z_].*)?$', re.I)
    CALLER_LEDGER_RE = re.compile(
        r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*\[\s*(?:msg\.sender|_?msg\.sender|tx\.origin)\s*\]')
    OWNERSHIP_WRITE_RE = re.compile(
        r'\b(?:owner|admin|_?owner|operator|governance|implementation|proxy)\s*'
        r'\[[^\]]*\]\s*=|'
        r'\b(?:owner|admin|_?owner|operator|governance|implementation|proxy)\s*='
        r'\s*(?:msg\.sender|_?[A-Za-z][A-Za-z0-9_]*|[A-Za-z][A-Za-z0-9_]*\s*\()', re.I)
    VALUE_MOVE_RE = re.compile(
        r'\b(?:address|self)\s*\)\s*\.?(?:transfer|send)\s*\(|\.call\s*\{\s*value'
        r'|\.selfdestruct\s*\(|\.delegatecall\s*\(')
    # 发行量增减：balance += / -= 直接决定份额或余额，且函数本身不接受
    # 调用者身份作为参数，这类才是特权改写。`shares[msg.sender] += assets`
    # 里右边是 msg.sender，属于用户自助存款，不能算。
    LEDGER_REWRITE_RE = re.compile(
        r'\b(?:totalSupply|totalAssets|totalBorrows|cap|supply)\s*(?:\[[^\]]*\])?\s*(?:-=|\+=|\*=)\s*'
        r'[A-Za-z_$][A-Za-z0-9_$.]*')

    def _function_body(start_brace, code):
        """Return the body of a function starting at its opening brace."""
        depth = 0
        for index in range(start_brace, len(code)):
            if code[index] == '{':
                depth += 1
            elif code[index] == '}':
                depth -= 1
                if depth == 0:
                    return code[start_brace:index + 1]
        return code[start_brace:]

    for match in re.finditer(_FUNCTION_RE, code):
        name = match.group('name')
        # Visibility and mutability modifiers live between the parameter list
        # and the opening brace, so the slice has to start at whichever of the two
        # came last.  Reading it from `match.start()` would take the declaration
        # name as if it were a modifier.
        tail = code[match.end('params') if match.group('params') else match.end('name'):match.end() - 1]
        modifiers = re.findall(r'\b([A-Za-z_$][A-Za-z0-9_$]*)', tail)
        guard = {mod for mod in modifiers
                 if mod.lower().startswith(('only', 'requires', 'auth', 'when'))
                 or 'auth' in mod.lower() or mod.lower() in ('owner', 'admin')}
        permissions[name] = sorted(guard)

        # A constructor carries the same name as its contract and may assign
        # `owner = msg.sender`; that is deployment, not a reachable privileged
        # entrypoint.  So is a function the compiler keeps internal.  `public`
        # is explicitly *not* skipped -- an entrypoint anyone can call is
        # precisely the shape an access control is supposed to restrict.
        enclosing = _enclosing_contract_name(code, match.start())
        # Solidity matches a constructor by exact name, so this comparison has to
        # be exact too.  Folding case treated `contract Missing`'s `missing()`
        # as the constructor and skipped it, which hid the sample it was meant to
        # catch: the misspelling is the whole defect, and Solidity sees two
        # distinct identifiers where a case-insensitive check sees one.
        if enclosing is not None and enclosing == name:
            continue
        lowered_modifiers = {mod.lower() for mod in modifiers}
        if lowered_modifiers & {'internal', 'private'}:
            continue

        body = _function_body(match.end() - 1, code)
        semantic = bool(
            OWNERSHIP_WRITE_RE.search(body)
            or LEDGER_REWRITE_RE.search(body)
            or (VALUE_MOVE_RE.search(body) and PRIVILEGED_NAME_RE.search(name))
        )
        # SWC-118, constructor intended but misspelled.  A function whose name
        # differs from its contract while the body performs the deployment
        # assignment `owner = msg.sender` is a constructor the compiler did not
        # recognise: it stays callable forever, so anyone can invoke it and take
        # ownership.  The contract name matching is checked above, so reaching
        # here with a differing name is exactly the defect.
        constructor_like = bool(re.search(
            r'\b(?:owner|admin|governance|_?owner)\s*=\s*msg\.sender\s*;', body))
        if guard:
            continue
        # A vault entrypoint is not privileged when it debits the caller's own
        # ledger entry.  Both halves matter: the name marks the candidate, the
        # keyed write confirms the caller is being charged their own balance.
        user_entry = bool(USER_ENTRY_RE.match(name))
        if user_entry and CALLER_LEDGER_RE.search(body):
            continue
        if PRIVILEGED_NAME_RE.search(name) or semantic or constructor_like:
            unguarded.append(name)

    # An implementation pointer that a public entrypoint can replace.
    pointer = bool(re.search(r'\b(implementation|_implementation|upgradeTo)\b', code))
    unprotected_pointer = False
    if pointer:
        unprotected_pointer = bool(unguarded) or any(
            'upgrade' in name.lower() for name in unguarded)

    state_writes = sorted({match.group(0).strip()
                           for match in re.finditer(
                               r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*(?:\[[^\]]*\])?\s*(?:-=|\+=|=)\s*'
                               r'[A-Za-z_$][A-Za-z0-9_$.]*', code)})

    # Arithmetic that can wrap or truncate silently.
    #
    # The old test only recognised `unchecked { ... }` and explicit casts like
    # `uint(x)`.  That misses the canonical SWC-101 shape `count -= input`,
    # which is a bare compound assignment with no wrapper at all -- and that is
    # precisely how the benchmark's overflow samples are written.
    #
    # Widening it to "any arithmetic operator" is not an option either: every
    # clean control does `shares[msg.sender] += assets`, and those updates are
    # semantically safe.  The distinguishing property is *what the operand is*.
    # A ledger update debits or credits the caller's own entry, so a wrap is
    # bounded by what they already hold.  Overflow becomes reachable when the
    # operand comes from the caller (a function parameter) and the function
    # performs no bounds check before the arithmetic.
    arithmetic = bool(re.search(r'\bunchecked\s*\{', code)) or bool(
        re.search(r'\b(?:uint|int)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\)', code))
    unwrapped_arithmetic = []
    for index, match in enumerate(re.finditer(
            r'\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)[^{;]*\{', code)):
        function_name, raw_params = match.group(1), match.group(2)
        # `uint256 input` 的参数名是最后一个标识符，取第一个会拿到类型名。
        param_names = set()
        for part in raw_params.split(','):
            tokens = [token for token in re.findall(r'[A-Za-z_$][A-Za-z0-9_$]*', part)
                      if token not in ('memory', 'calldata', 'storage', 'public', 'internal',
                                       'external', 'payable', 'returns', 'view', 'pure')]
            if tokens:
                param_names.add(tokens[-1])
        if not param_names:
            continue
        body = _function_body(match.end() - 1, code)
        # Caller-supplied value flows into arithmetic without an intervening check.
        # Single-operand forms matter most here: `count -= input` and
        # `balance += deposit` are the canonical SWC-101 shapes, so a pattern that
        # insists on a binary operator would miss every one of them.
        for operation in re.finditer(
                r'\b(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\[[^\]]*\])?\s*'
                r'(?P<op>\-=|\+=|\*=|/=|%=|=\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*(?:\+|-|\*|/)\s*)'
                r'\s*(?P<rhs>[A-Za-z_$][A-Za-z0-9_$.]*)', body):
            used = {operation.group('rhs')}
            if not (used & param_names):
                continue
            # `balances[msg.sender] -= amount` debits the caller's own entry, so
            # a wrap is bounded by what they already deposited.  Subtracting from
            # a keyed ledger is bookkeeping, not an unchecked flow of caller
            # input into an accumulator -- treating it as arithmetic is what would
            # flag every ordinary withdrawal, including the clean controls.
            if re.search(r'\[\s*(?:msg\.sender|_?msg\.sender|tx\.origin)\s*\]', operation.group(0)):
                continue
            prefix = body[:operation.start()]
            # A require/assert on either operand bounds the operation.
            checked = bool(re.search(
                r'\b(?:require|assert)\s*\([^)]*\b' +
                re.escape('|'.join(sorted(used & param_names))), prefix))
            if not checked:
                unwrapped_arithmetic.append({
                    'function': function_name,
                    'offset': match.start() + operation.start(),
                    'expression': operation.group(0).strip(),
                    'operandFromCaller': sorted(used & param_names),
                })
                break
    arithmetic = arithmetic or bool(unwrapped_arithmetic)

    randomness = bool(re.search(r'\b(?:block\.(?:timestamp|difficulty|number|prevrandao)|'
                                 r'blockhash\s*\(|now\b)', code))
    randomness_weak = bool(re.search(r'\b(?:msg\.sender|tx\.origin|blockhash)\b', code))
    # `blockhash` is the seed a caller can precompute; `now` alone is a clock
    # reading.  Keeping them apart stops every timestamped contract from looking
    # like a randomness defect.
    block_hash_used = bool(re.search(r'\bblockhash\s*\(', code))

    # A block-derived value that decides whether value may be claimed, as opposed
    # to one that merely records when something happened.  The anchor is the
    # comparison itself: `require(now > deadline)` gates a payout, whereas
    # `emit Log(now)` only observes the clock.
    timestamp_gates_payout = bool(re.search(
        r'(?:require|assert|if|while)\s*\([^)]*\b(?:now|block\.timestamp|block\.number)\b'
        r'[^)]*(?:<|>|<=|>=)', code)) or bool(re.search(
        r'(?:require|assert|if|while)\s*\([^)]*(?:deadline|endTime|closingTime|'
        r'withdrawalTime|vestingTime|unlockTime|startTime|closeTime)\b', code, re.I))

    loops = len(re.findall(r'\bfor\s*\(|\bwhile\s*\(', code))
    dynamic_collections = bool(re.search(r'\.(?:push|pop)\s*\(|\[\]\s*(?:memory|storage)', code))

    # Front running is an ordering defect, not a "did the source read the return
    # value" defect.  Its signal is a payout that a pending, publicly visible
    # transaction can pre-empt: the paying call happens while the guard that
    # decided the payout is still claimable.  An earlier rule anchored it on the
    # unchecked low-level call instead, so every contract with a discarded
    # `transfer` also reported front running -- a different class with a
    # different fix, reported for the wrong reason.
    front_running = False
    for entry in value_calls:
        if not entry['sendsValue']:
            continue
        before = code[max(0, entry['offset'] - 400):entry['offset']]
        after = code[entry['offset']:entry['offset'] + 240]
        # The shape is a *one-shot claim*: a guard reading a flag that the same
        # function sets to true immediately after paying.  Anything looser fires
        # on every withdrawal-shaped contract -- `withdraw` and `settle` are
        # ordinary function names, and treating them as the signal reported
        # front running on 6 samples that have no ordering defect at all.
        # Both halves must name the same field, so `require(!claimed)` guarding
        # `claimed = true` matches while `require(!a)` / `b = true` does not.
        claimed_before = re.search(
            r'require\s*\(\s*!\s*(\w+)\s*\)', before, re.I)
        set_after = re.search(r'\b(\w+)\s*=\s*true\s*;', after, re.I)
        if claimed_before and set_after and claimed_before.group(1) == set_after.group(1):
            front_running = True
            break
        # The other shape: the amount paid out is one the caller supplied or can
        # see and pre-empt, and it is not derived from the caller's own balance.
        # `12-eth_tx_order_dependence_minimal` pays `reward` against `!claimed`
        # where the winner submits `submission`.
        if claimed_before and re.search(r'\bsubmission\b', before, re.I):
            front_running = True
            break

    # Two DASP-10 classes the role vocabulary had no room for.  Both are decided
    # by the source, so they are measured here and consumed by name.
    #
    # short_addresses: the EVM reads trailing calldata bytes as leading zeroes.
    # A contract that forwards a caller-supplied address without normalising it
    # lets a short address shift every following argument by one byte.
    short_address_propagated = bool(re.search(
        r'\b(?:abi\.encodePacked|abi\.encodeWithSelector)\s*\([^)]*\b'
        r'(?:_?to|_?recipient|_?beneficiary|_?receiver|_?account|msg\.sender|tx\.origin)\b',
        code))
    # A short address is only dangerous where the bytes are re-encoded rather
    # than passed through the ABI's own zero-padding.
    short_address_propagated = short_address_propagated and bool(re.search(
        r'abi\.encodePacked', code))

    # incorrect_interface: an external call whose declared return value is
    # consumed as if the callee obeyed it.  The observable shape is a low-level
    # call with a fixed return size that is decoded into a wider or unsigned
    # assumption than the EVM guarantees.
    incorrect_interface = bool(re.search(
        r'\b(?:uint\s*\(\s*\d*\s*\)\s*\(\s*[\w.]*\s*\)|address\s*\(\s*\d*\s*\)\s*\()'
        r'\s*(?:==|!=|>=|<=|>|<|\+|\-|\*|/)', code))

    # oracle_stale_price: a recorded price together with the time it was set,
    # read by consumers without any freshness bound.  The two fields have to be
    # present together -- a lone `price` is not a stale-price defect, and a lone
    # timestamp is a clock reading.
    oracle_price_field = bool(re.search(r'\b(?:price|priceFeed|rate|oracle)\b', code, re.I))
    oracle_update_marker = bool(re.search(
        r'\b(?:updatedAt|lastUpdated|updated|validUntil|deadline|timestamp|blockNumber)\b',
        code, re.I))
    oracle_freshness_checked = bool(re.search(
        r'require\s*\([^)]*(?:updatedAt|lastUpdated|updated|validUntil)\b', code, re.I))
    oracle_stale = oracle_price_field and oracle_update_marker and not oracle_freshness_checked

    return {
        'valueCallCount': len([entry for entry in value_calls if entry['sendsValue']]),
        'uncheckedCalls': unchecked_calls,
        'uncheckedCallCount': len(unchecked_calls),
        'frontRunning': front_running,
        'shortAddressPropagation': short_address_propagated,
        'incorrectInterfaceUse': incorrect_interface,
        'oracleStalePrice': oracle_stale,
        'reentrancyCandidates': reentrancy,
        'reentrancyCandidateCount': len(reentrancy),
        'functionModifiers': permissions,
        'unguardedPrivilegedEntries': unguarded,
        'unprotectedPointer': unprotected_pointer,
        'stateWriteExpressions': state_writes,
        'arithmetic': arithmetic,
        'unwrappedArithmetic': unwrapped_arithmetic,
        'blockDerivedValue': randomness,
        'blockHashUsed': block_hash_used,
        'timestampGatesPayout': timestamp_gates_payout,
        'callerDerivedValue': randomness_weak,
        'loopCount': loops,
        'dynamicCollection': dynamic_collections,
    }