"""Small helpers shared by assertion renderers."""

import re


_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


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
    """Validate a getter reference and return the Solidity expression to call.

    A getter is stored as its full signature so the call site stays unambiguous:
    ``balanceOf()`` for a public scalar, ``balances(address)`` for a public
    mapping.  A bare ``balances`` is also accepted and read as the scalar form,
    because that is how the IR names a state field and how several roles already
    record a guard that has no argument list at all.

    Only one shape of argument is accepted: a single ``address``.  That keeps the
    rendered call a pure read of a known slot.  Arbitrary argument expressions
    would mean encoding values the assertion has no business choosing, and a
    multi-argument getter has no single value to compare.
    Returns ``None`` when the value is not a callable signature.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if _IDENTIFIER.fullmatch(text):
        return f"{text}()"
    match = re.fullmatch(r"([A-Za-z_$][A-Za-z0-9_$]*)\(\s*(address)?\s*\)", text)
    if not match:
        return None
    name, argument = match.group(1), match.group(2)
    if not argument:
        return f"{name}()"
    # The mapping key is the calling contract, which is a stable, always-defined
    # address here and does not depend on the sequence of calls under test.
    return f"{name}({address_expr})"


def static_read(address, signature, label, ok_name=None, data_name=None):
    """Emit a state-reading external call that works on 0.4.x through 0.8.x.

    ``address.staticcall`` only exists from 0.5 on, and the benchmark corpus pins
    compilers back to 0.4.10, so the read is issued as a plain ``call``.  The
    caller names its own variables because several assertions read the same
    field more than once under different suffixes (``guardOk`` / ``guardOk2``),
    which a label-derived name would not reproduce.
    """
    ok_name = ok_name or f"{label}Ok"
    data_name = data_name or f"{label}Data"
    return _low_level_read(address, _encoded_call(signature), label,
                           ok_name=ok_name, data_name=data_name)


def _encoded_call(signature):
    """The ``abi.encode...`` expression for one resolved getter reference.

    ``abi.encodeWithSignature`` takes a signature *string*, so passing the Solidity
    call expression ``balances(address(this))`` encodes the literal text
    ``address(this)`` as the parameter type name and the target finds no matching
    function.  A getter that takes an argument is therefore encoded from its
    canonical type-only signature plus the argument values as separate arguments.

    That variadic form is itself 0.5+, so the encoding goes through the harness's
    own ``_encodeCall`` helper instead of being spelled inline: the helper hashes
    the signature inside ``assembly`` and appends the ABI-encoded argument, which
    parses on every release the corpus pins.  The corpus still contains 0.4.x
    samples, and inlining the modern form made every assertion against a public
    mapping fail to compile there.
    """
    match = re.fullmatch(r"([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)", signature.strip())
    if not match or not match.group(2).strip():
        return f'abi.encodeWithSignature("{signature.strip()}")'
    name, arguments = match.group(1), match.group(2)
    values = [argument.strip() for argument in arguments.split(",") if argument.strip()]
    types = ",".join("address" for _ in values)
    return f'_encodeCall("{name}({types})", {", ".join(values)})'


def entry_call(address, signature, label):
    """Invoke a zero-argument entrypoint and expose only whether it succeeded.

    The tuple result of a low-level call cannot be destructured inline before 0.5,
    so the variables are declared and then assigned.  Only the success flag is
    surfaced: the access-control and batch assertions are about whether a call was
    admitted, and keeping the return data out avoids depending on a decode shape
    the template never chose.
    """
    ok_name = f"{label}Ok"
    data_name = f"{label}Data"
    return (
        f"bool {ok_name} = false; bytes memory {data_name} = new bytes(0); "
        f"(bool {ok_name}Raw, bytes memory {data_name}Raw) = "
        f"{address}.call(abi.encodeWithSignature(\"{signature}\")); "
        f"{ok_name} = {ok_name}Raw; {data_name} = {data_name}Raw;"
    )


def _low_level_read(address, encoded, label, ok_name, data_name):
    # Two dialect facts force this shape rather than the obvious one.
    #
    # First, a low-level call's tuple result cannot be destructured inline before
    # 0.5: `(bool ok, bytes memory d) = target.call(payload);` is a parse error on
    # the 0.4 compilers, so the variables are declared and then assigned.
    #
    # Second, the declared names have to be unique: two reads of the same field in
    # one function collided on shared temporaries and failed to compile.  The label
    # keeps them distinct without making them unreadable.
    #
    # `address.staticcall` is deliberately not used -- it only exists from 0.5 on,
    # and a `call` whose result this assertion reads without acting on it cannot
    # change the target's state.
    return (
        f"bool {ok_name} = false; bytes memory {data_name} = new bytes(0); "
        f"{{ bool {ok_name}Raw = false; bytes memory {data_name}Raw = new bytes(0); "
        f"({ok_name}Raw, {data_name}Raw) = {address}.call({encoded}); "
        f"{ok_name} = {ok_name}Raw; {data_name} = {data_name}Raw; }}"
    )


def read_expr(address, field, label):
    # The callee is addressed through a local of its own rather than cast at the
    # call site.  Assigning the target's expression to an `address` local needs
    # no explicit `address(...)`: the harness deploys into an address-typed
    # variable, so this holds on the 0.4 compilers and the 0.8 ones alike.
    return (
        f"address {label}Target = {address}; uint256 {label}; "
        + static_read(f"{label}Target", f"{field}()", label) +
        f' require({label}Ok && {label}Data.length >= 32, "{label} getter unavailable"); '
        f"{label} = abi.decode({label}Data, (uint256));"
    )


def guard(params, context, *fields):
    address = target(context)
    tol = tolerance(params)
    names = [identifier(params, field) for field in fields]
    if address is None or tol is None or any(name is None for name in names):
        return None
    return address, tol, names


def ratio_assertion(left, right, tolerance_bps, message):
    return (
        f"require({left} * 10000 >= {right} * (10000 - {tolerance_bps}), "
        f'\"{message}\");'
    )
