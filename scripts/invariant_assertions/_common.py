"""Small helpers shared by assertion renderers.

Every construct emitted here was verified against the compilers this corpus
pins, because a generated assertion that does not compile is reported by the
deep layer as an unavailable deployment or an unreadable precondition -- a
failure caused by the harness rather than by the contract under test.  Compiling
each obvious spelling against the cached soljson releases gives:

    form                                          0.4.10-0.4.21   0.4.24-0.4.25   0.5+
    (bool ok, bytes memory d) = t.call(p)         parse error     type error      ok
    abi.decode(data, (uint256))                   undeclared      no such member ok
    abi.encodeWithSignature("f()")                undeclared      ok              ok
    shr(value, 96)                                undeclared      undeclared      ok
    returndatasize                                pre-0.4.18      ok              needs ()
    pure                                          reserved word   ok              ok
    (only, ) = f()                                n/a -- needs a two-value callee

The last row is why there are two call helpers rather than one.  Discarding a
tuple component with a trailing comma only parses when the callee actually
returns two values, and a boolean-only callee makes the compiler report
"Type bool is not implicitly convertible to expected type tuple(bool,)" on every
release from 0.4.22 to 0.8.  So :func:`read_value` and :func:`call_succeeded`
are separate, and neither is asked to discard anything.

What remains -- a seven-argument `assembly` call into an explicit memory buffer,
a selector hashed inside `assembly` from a `string memory` length, and `div`
rather than `shr` -- parses on every release the corpus pins.
"""

import re


_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

# Harness helpers.  Renderers never call `.call()` or `abi.decode` themselves:
# those are the two constructs no dialect in the corpus accepts, so the call
# lives in one place whose spelling is verified.
READ_WORD = "_readWord"
CALL_SUCCEEDED = "_callSucceeded"
ENCODE_SELECTOR = "_encodeSelector"
ENCODE_SELECTOR_WITH_ADDRESS = "_encodeSelectorWithAddress"
ENCODE_SELECTOR_WITH_UINT256 = "_encodeSelectorWithUint256"
# Probes for entry points that take arguments.  Admission is the question these
# assertions ask, so the argument is a placeholder rather than a value read
# back: an index of zero for an array position, this contract for an address the
# entry point would otherwise have to trust, and empty bytes for a payload whose
# contents the probe never inspects.
ENCODE_SELECTOR_WITH_BYTES = "_encodeSelectorWithBytes"
ENCODE_SELECTOR_WITH_TWO_UINT256 = "_encodeSelectorWithTwoUint256"

# `require` accepted a revert-reason argument only from 0.4.22 on; before that the
# two-argument form is a type error, so the renderer has to emit the bare one.
_REQUIRE_REASON_FLOOR = (0, 4, 22)


def _compiler_version(context):
    value = context.get("compiler_version") if isinstance(context, dict) else None
    if not isinstance(value, str):
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    return tuple(int(part) for part in match.groups()) if match else None


def require_statement(context, condition, message):
    """Emit ``require`` in the dialect the target's own compiler accepts.

    The revert reason is the whole point of the message -- it is what
    distinguishes an unreadable precondition from a violated protocol property
    in the recorded evidence -- so it is kept wherever the compiler allows one.
    A compiler the renderer cannot identify takes the modern branch, which is
    the side that fails loudly rather than dropping the diagnosis.
    """
    version = _compiler_version(context)
    if version is not None and version < _REQUIRE_REASON_FLOOR:
        return f"require({condition});"
    return f'require({condition}, "{message}");'


def identifier(params, key):
    value = params.get(key)
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        return None
    return value


def target(context):
    value = context.get("target_addr_expr") if isinstance(context, dict) else None
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def tolerance(params):
    value = params.get("toleranceBps", 0)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000:
        return None
    return value


def call_expression(value, address_expr="address(this)"):
    """Validate a getter reference and return the Solidity signature to encode.

    A getter is stored as its full signature so the call site stays unambiguous:
    ``balanceOf()`` for a public scalar, ``balances(address)`` for a public
    mapping.  A bare ``balances`` is also accepted and read as the scalar form,
    because that is how the IR names a state field and how several roles already
    record a guard that has no argument list at all.

    Only the shapes this layer can encode without inventing values are accepted:
    no arguments, or a single ``address``.  A multi-argument getter has no single
    slot to read, and encoding a value the assertion did not choose would make
    the comparison meaningless.  Returns ``None`` when the value is not callable.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if _IDENTIFIER.fullmatch(text):
        return f"{text}()"
    match = re.fullmatch(r"([A-Za-z_$][A-Za-z0-9_$]*)\(\s*(address|uint256)?\s*\)", text)
    if not match:
        return None
    name, argument = match.group(1), match.group(2)
    if argument is None:
        return f"{name}()"
    # The mapping key is the calling contract, which is a stable, always-defined
    # address here and does not depend on the sequence of calls under test.
    return f"{name}({argument})"


def encoded_call(signature, argument_expr=None):
    """The ``bytes`` expression carrying one call's calldata.

    ``abi.encodeWithSignature`` is undeclared before 0.4.22, and passing the
    Solidity call expression ``balances(address(this))`` *inside* the signature
    string makes the target look for a parameter type named ``address(this)``,
    which it never implements -- the read then reverts and is reported as an
    unreadable precondition.  So the argument travels as a value alongside a
    canonical type-only signature.  ``abi.encodeWithSelector`` is not an option
    either: it needs the one-argument ``keccak256`` that does not exist before
    0.5, so the selector is hashed inside `assembly` by the harness helper.
    """
    text = signature.strip()
    if argument_expr is None:
        if "(" not in text:
            return f'{ENCODE_SELECTOR}("{text}")'
        # A signature with a non-empty parameter list needs its arguments
        # filled in before it addresses anything.  Encoding the bare selector
        # for `changeOwner(address)` would dispatch to nothing, and the missing
        # return data reads as a revert -- which is exactly the shape of a
        # violated property.  The placeholder encoder is the one that knows
        # which parameter types it can carry.
        return encoded_entry_call(text)
    if "uint256" in text:
        return f'{ENCODE_SELECTOR_WITH_UINT256}("{text}", {argument_expr})'
    return f'{ENCODE_SELECTOR_WITH_ADDRESS}("{text}", {argument_expr})'


def encoded_entry_call(signature):
    """The ``bytes`` expression carrying a zero-argument probe of an entry point.

    Access control and batch assertions are about *admission*, not about what the
    call returns, so an entry point that takes arguments can still be probed: the
    arguments are placeholders chosen to be inert, and only the success flag is
    read.  Restricting these templates to zero-argument entry points meant every
    sample whose privileged setter takes an address or an index -- which is most
    of them -- was recorded as needing an adapter and never entered forge, even
    though the entry point was sitting in the IR with its full signature.

    Each supported type is encoded by the harness helper that already carries the
    verified selector layout, because the one-argument ``keccak256`` that
    ``abi.encodeWithSelector`` needs does not exist before 0.5.

    ``None`` is returned for a signature the caller should not probe -- an
    unsupported parameter type, more arguments than any helper can carry, or text
    that is not a canonical signature at all.
    """
    text = (signature or "").strip()
    if any(char in text for char in "\"'`\n\r{}") or not text:
        return None
    # `encoded_call` delegates here for a signature that takes arguments, so the
    # bare-selector form is spelled out directly here.  Calling back into
    # `encoded_call` would hand it the same signature and loop.
    if "(" not in text:
        return f'{ENCODE_SELECTOR}("{text}")' if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", text) else None
    match = re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*\(([^()]*)\)", text)
    if not match:
        return None
    arguments = [part.strip() for part in match.group(1).split(",")] if match.group(1) else []
    if not arguments:
        return f'{ENCODE_SELECTOR}("{text}")'
    if len(arguments) > 2:
        # No helper carries three or more words; the probe stays unavailable
        # rather than guessing an encoding the target may not accept.
        return None
    if arguments == ["address"]:
        return f'{ENCODE_SELECTOR_WITH_ADDRESS}("{text}", address(this))'
    if arguments == ["uint256"]:
        return f'{ENCODE_SELECTOR_WITH_UINT256}("{text}", 0)'
    if arguments == ["bytes"]:
        return f'{ENCODE_SELECTOR_WITH_BYTES}("{text}")'
    if arguments == ["uint256", "uint256"]:
        return f'{ENCODE_SELECTOR_WITH_TWO_UINT256}("{text}", 0, 0)'
    return None


def _mapping_argument(signature):
    """The value a single-argument mapping getter is read through, if it has one.

    A public mapping compiles to a getter taking one ``address``, and the
    assertion reads the entry belonging to itself.  A getter with any other
    arity has no single slot to read and takes no argument here.
    """
    text = (signature or "").strip()
    if text.endswith("(address)") and text.count(",") == 0:
        return "address(this)"
    return None


def read_value(address, signature, ok_name, value_name, argument_expr=None):
    """Read one word of a callee's state into two declared locals.

    The result is assigned to pre-declared variables inside a block rather than
    destructured at the call site: an inline ``(a, b) = f()`` is a parse error
    before 0.4.24 and a type error from 0.4.24 to 0.4.25.  The names are required
    rather than derived because several assertions read the same field more than
    once under different suffixes (``guardOk`` / ``guardOk2``), which a
    label-derived name would not reproduce.
    """
    payload = encoded_call(signature, argument_expr)
    return "\n".join((
        f"bool {ok_name};",
        f"uint256 {value_name};",
        "{",
        f"    bool {ok_name}Raw;",
        f"    uint256 {value_name}Raw;",
        f"    ({ok_name}Raw, {value_name}Raw) = {READ_WORD}({address}, {payload});",
        f"    {ok_name} = {ok_name}Raw;",
        f"    {value_name} = {value_name}Raw;",
        "}",
    ))


def call_succeeded(address, signature, ok_name, argument_expr=None):
    """Invoke a callee and expose only whether the call was admitted.

    The access-control and batch assertions are about admission, so only the
    success flag is surfaced.  A single-value callee keeps the caller from
    needing to discard a tuple component, which no 0.4.x compiler accepts.

    The assignment is *not* written as ``bool name = f();`` for an already
    declared local: a template that calls this twice under the same name -- which
    the access-control assertion does, once for the entry and once through
    :func:`read_value` -- then declares it twice and the harness fails to compile
    with "Identifier already declared".  A bare assignment to a declared local is
    the form that stays valid in both situations, so callers declare the name.
    """
    payload = encoded_call(signature, argument_expr)
    if payload is None:
        # The signature takes arguments the probe cannot fill in.  Falling back
        # to the entry-point encoder keeps an entry point such as
        # `setImplementation(address)` reachable; a type it cannot carry still
        # refuses, and the renderer reports the assertion as unavailable rather
        # than emitting a call that dispatches to nothing.
        payload = encoded_entry_call(signature)
    if payload is None:
        return None
    return f"{ok_name} = {CALL_SUCCEEDED}({address}, {payload});"


def read_expr(address, field, label, context=None):
    """Read one word of target state into a plain ``uint256`` local.

    The callee is addressed through a local of its own rather than cast at the
    call site.  Assigning the target's expression to an ``address`` local needs
    no explicit ``address(...)``: the harness deploys into an address-typed
    variable, so this holds on the 0.4 compilers and the 0.8 ones alike.

    Only the value survives the block.  Keeping the success flag as a second
    outer local doubled the number of simultaneously live locals, and a
    before/after pair across two fields then exceeded the legacy 16-slot stack:
    0.4.15 through 0.4.25 rejected the harness with "Stack too deep", which the
    deep layer reported as an unavailable deployment.  Those releases have no
    `via_ir` to relieve it, so the pressure has to come out of the generated
    code instead -- and the flag's only use is the precondition check, which
    belongs inside the block anyway.

    Each call still needs a distinct ``label``: the locals are declared in the
    assertion's own scope, so a template that reads the same field twice names
    the pair ``...Before`` and ``...After`` and the two do not collide.

    The address is used as the callee expression directly rather than copied
    into a local of its own.  Each snapshot otherwise held two address locals
    plus its value, and an ERC-4626 share-price assertion takes four snapshots:
    that is eight live slots against the legacy 16-slot stack the 0.4.x
    codegen enforces with no ``via_ir`` to relieve it, so those compilers
    rejected the harness with "Stack too deep" before the property was ever
    checked.  The expression is already an address-typed local in the harness --
    it is the test's own ``target`` -- so re-stating it bought nothing.

    A parameterised getter encodes the caller address as a value, not inside the
    signature string: ``balances(address)`` is a different selector from
    ``balances(address(this))``, and the latter dispatches to nothing.
    """
    signature = call_expression(field)
    if signature is None:
        return None
    return "\n".join((
        f"uint256 {label};",
        "{",
        f"    bool {label}Ok;",
        f"    uint256 {label}Value;",
        f"    ({label}Ok, {label}Value) = {READ_WORD}({address}, "
        f"{encoded_call(signature, _mapping_argument(signature))});",
        "    " + require_statement(context, f"{label}Ok", f"{label} getter unavailable"),
        f"    {label} = {label}Value;",
        "}",
    ))


def guard(params, context, *fields):
    address = target(context)
    tol = tolerance(params)
    names = [identifier(params, field) for field in fields]
    if address is None or tol is None or any(name is None for name in names):
        return None
    return address, tol, names


def ratio_assertion(left, right, tolerance_bps, message, context=None):
    return require_statement(context, f"{left} * 10000 >= {right} * (10000 - {tolerance_bps})",
                             message)