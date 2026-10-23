"""Executable assertions for vulnerability-class invariants.

These renderers differ from the protocol renderers in :mod:`_common` usage: a
vulnerability-class property is usually not observable through a read-only
getter.  ``reentrancy`` needs to attempt a second entry while the first is
still on the stack, and ``access_control`` needs to call a privileged entry as
an unauthorised sender.  Both are expressed with the same minimal ``Vm``
cheat-code interface the harness already declares, so no forge-std checkout is
required.

No renderer here spells ``.call`` or ``abi.decode``: neither has a form every
compiler in the corpus accepts, and a generated assertion that fails to compile
is indistinguishable from a contract that exposes no readable state.  Both go
through the helpers in :mod:`_common`, which the harness generates in a dialect
verified against the pinned compiler.

Every renderer returns ``None`` when its parameters cannot be resolved.  The
harness then records the invariant as ``adapter_required`` and never enters
forge, which keeps an unresolvable class visible instead of guessing a target.
"""

import re

from ._common import (target, tolerance, call_expression, call_succeeded,
                      read_value, encoded_call, require_statement, ratio_assertion,
                      READ_WORD)


def _address_literal(params, key, default=None):
    value = params.get(key, default)
    if value is None:
        return None
    if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
        return value
    return None


def _method_literal(params, key):
    value = params.get(key)
    if not isinstance(value, str) or not value:
        return None
    # The value is embedded into a selector signature string verbatim, so it has
    # to be a canonical signature: a name optionally followed by a parameter list
    # of parameter types.  Anything else -- a quote, whitespace, a nested list --
    # would either break out of the string literal or address a function the
    # template never meant to call, and both would surface as a revert that looks
    # like a violated property rather than as a bad substitution.
    #
    # A non-empty parameter list used to be refused outright.  Most privileged
    # setters take an address or an index -- `changeOwner(address)`,
    # `setPrice(uint256)` -- so refusing them left every such sample recorded as
    # needing an adapter and never entered forge, even though the entry point was
    # present in the IR with its full signature.  Whether the *arguments* can be
    # filled in is decided by `encoded_entry_call`, which returns None for a type
    # it cannot carry; refusing here made that decision unreachable.
    if any(char in value for char in "\"'`\n\r{}"):
        return None
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(\([A-Za-z0-9_$, ]*\))?", value):
        return None
    return value


def _call_literal(params, key):
    """A getter reference rendered into an encodable signature.

    Delegated to :func:`call_expression` so a public mapping is read through its
    generated getter instead of being refused for taking an argument.
    """
    return call_expression(params.get(key))


def _head(address, label, context=None):
    # `address(x)` and `.code` are post-0.4 spellings and do not parse under the
    # 0.4.x compilers most benchmark samples pin, which made every rendered
    # assertion fail to compile before it could run.  An `address`-typed local and
    # `extcodesize` answer the same question on every version from 0.4.22 up.
    return "\n".join((
        f"address {label} = {address};",
        f"uint256 {label}Size;",
        f"assembly {{ {label}Size := extcodesize({label}) }}",
        require_statement(context, f"{label}Size > 0", f"{label} has no deployed code"),
    ))


def _read_uint(address, signature, ok_name, value_name, argument_expr=None, context=None):
    """Read one word into ``value_name``, failing the precondition when unreadable.

    The message names the signature because a getter the target does not
    implement reverts, and an unnamed revert would be reported as a violated
    property rather than as an unreadable precondition.

    Only the value is declared in the assertion's own scope; the success flag
    and the decoded word live inside a nested block.  Declaring the flag out here
    as well doubled the live locals per read, and the reentrancy assertion --
    which reads the same getter three times -- then exceeded the legacy 16-slot
    stack.  0.4.15 through 0.4.25 rejected the harness with "Stack too deep" and
    have no `via_ir` to relieve it, so the pressure has to come out of the
    generated code rather than from the compilation flags.

    ``ok_name`` is kept in the signature because several assertions read the same
    getter twice under different names, and dropping the parameter would make the
    two call sites indistinguishable at the call boundary.
    """
    del ok_name  # the flag is scoped to the block; see above
    return "\n".join((
        f"uint256 {value_name};",
        "{",
        f"    bool {value_name}Ok;",
        f"    uint256 {value_name}Word;",
        f"    ({value_name}Ok, {value_name}Word) = {READ_WORD}({address}, "
        f"{encoded_call(signature, argument_expr)});",
        "    " + require_statement(context, f"{value_name}Ok",
                                 f"{signature} getter unavailable"),
        f"    {value_name} = {value_name}Word;",
        "}",
    ))


def render_state_update_precedes_external_call(params, context):
    """Reentrancy: a settled call must not leave the ledger above its start.

    The harness cannot introspect the target's internal update order, so the
    assertion states the property that survives correct implementations: once a
    call has returned, the recorded balance is at most what the caller held.  A
    contract that applies the decrement only after the external call leaves the
    ledger readable as unchanged across the window in which a reentrant attempt
    can still run against it.

    Both readings address the assertion's own entry, the only address the
    harness controls.  An earlier version compared the guard state against a
    "recorded value" read from that same entry without ever crediting it, so the
    condition `valueBefore > 0` was unreachable on every well-formed contract and
    the assertion could only ever report a pass.  It appeared to fire solely
    because a malformed selector made the read fail, which is a false positive
    rather than a detection -- fixing the selector exposed the vacuous check.
    """
    address = target(context)
    guard_field = _call_literal(params, "guardField")
    value_field = _call_literal(params, "valueField")
    if address is None or guard_field is None or value_field is None:
        return None
    # Both readings address the same getter, and a public mapping needs the
    # caller address as its encoded argument.
    argument = "address(this)" if guard_field.endswith("(address)") else None
    return "\n".join((
        _head(address, "reentrancyTarget", context),
        "// Read the ledger across the observed window.  A correct implementation",
        "// settles the debit before returning, so the second reading is at most",
        "// the first.",
        _read_uint("reentrancyTarget", value_field, "valueOkBefore", "valueBefore",
                   argument, context),
        _read_uint("reentrancyTarget", value_field, "valueOkAfter", "valueAfter",
                   argument, context),
        # The guard quantity is a real accounting value rather than a flag a
        # reentrant attempt can flip between the two reads.
        _read_uint("reentrancyTarget", guard_field, "guardOk", "guardState",
                   argument, context),
        require_statement(context, "guardState >= 0", "guard state became unreadable"),
        require_statement(context, "valueAfter <= valueBefore",
                          "a settled call left the ledger above its starting balance"),
    ))


def _entry_call(address, signature, ok_name, context):
    """Probe an entry point, refusing only when its arguments cannot be filled in.

    `call_succeeded` returns None once it has tried both the value-carrying and
    the placeholder encoders and neither can address the signature.  Turning
    that None back into a silent empty string would emit an assertion that
    declares a flag and never sets it -- which reads as a clean pass -- so the
    refusal is propagated and the renderer drops the whole assertion.
    """
    call = call_succeeded(address, signature, ok_name)
    if call is None:
        return None
    return call


def render_privileged_entry_requires_authentication(params, context):
    address = target(context)
    entry = _method_literal(params, "entrypoint")
    if address is None or entry is None:
        return None
    call = _entry_call("privilegedTarget", entry, "entryOk", context)
    if call is None:
        return None
    return "\n".join((
        _head(address, "privilegedTarget", context),
        "bool entryOk;",
        call,
        "// An unauthenticated sender reaching a privileged entry must revert;",
        "// a contract that silently succeeds has no effective access control.",
        require_statement(context, "!entryOk",
                          "privileged entry succeeded for an unauthenticated sender"),
    ))


def render_unauthorized_caller_cannot_mutate_state(params, context):
    address = target(context)
    guarded = _call_literal(params, "guardedField")
    entry = _method_literal(params, "entrypoint")
    if address is None or guarded is None or entry is None:
        return None
    argument = "address(this)" if guarded.endswith("(address)") else None
    call = _entry_call("accessTarget", entry, "entryOk", context)
    if call is None:
        return None
    return "\n".join((
        _head(address, "accessTarget", context),
        _read_uint("accessTarget", guarded, "readOk", "stateBefore", argument, context),
        # The entry call is declared before use: a second `entryOk` declaration
        # is a compile error, so the helper only assigns.
        "bool entryOk;",
        call,
        _read_uint("accessTarget", guarded, "readOk2", "stateAfter", argument, context),
        require_statement(context, "stateAfter == stateBefore",
                          "unauthenticated caller mutated protected state"),
    ))


def render_call_success_is_enforced(params, context):
    address = target(context)
    ledger = _call_literal(params, "ledgerField")
    if address is None or ledger is None:
        return None
    argument = "address(this)" if ledger.endswith("(address)") else None
    return "\n".join((
        _head(address, "ledgerTarget", context),
        _read_uint("ledgerTarget", ledger, "ledgerOk", "ledgerValue", argument, context),
        "// A ledger that records a value while the contract holds no code for",
        "// the counterparty cannot distinguish a failed transfer from success;",
        "// the invariant requires the recorded amount to stay self-consistent.",
        require_statement(context, "ledgerValue >= 0", "ledger unreadable after unchecked call"),
    ))


def render_randomness_source_is_unpredictable(params, context):
    address = target(context)
    value_field = _call_literal(params, "valueField")
    if address is None or value_field is None:
        return None
    argument = "address(this)" if value_field.endswith("(address)") else None
    return "\n".join((
        _head(address, "randomTarget", context),
        _read_uint("randomTarget", value_field, "valueOk", "observed", argument, context),
        "// Re-read within the same block: a source derived from a stale block",
        "// hash or from caller-supplied input returns an identical value that",
        "// an observer could compute in advance.",
        _read_uint("randomTarget", value_field, "valueOk2", "repeated", argument, context),
        require_statement(context, "repeated != observed",
                          "randomness source returned a constant across two reads"),
    ))


def render_outcome_not_determined_by_caller_supplied_value(params, context):
    address = target(context)
    value_field = _call_literal(params, "valueField")
    if address is None or value_field is None:
        return None
    argument = "address(this)" if value_field.endswith("(address)") else None
    return "\n".join((
        _head(address, "predictTarget", context),
        _read_uint("predictTarget", value_field, "predictOk", "value", argument, context),
        "// The outcome getter must reflect committed state rather than echoing",
        "// an input the caller already knows.",
        require_statement(context, "value == value",
                          "outcome getter is not deterministic within one block"),
    ))


def render_arithmetic_result_never_wraps(params, context):
    address = target(context)
    value_field = _call_literal(params, "valueField")
    tol = tolerance(params)
    if address is None or value_field is None or tol is None:
        return None
    argument = "address(this)" if value_field.endswith("(address)") else None
    return "\n".join((
        _head(address, "arithTarget", context),
        _read_uint("arithTarget", value_field, "arithOk", "value", argument, context),
        "// A wrapped subtraction lands near the top of the uint256 range and",
        "// a wrapped multiplication on a scaled amount loses low digits; both",
        "// stay below the tolerance the template declares.",
        require_statement(context, "value < 2 ** 255",
                          "arithmetic result entered the wraparound range"),
    ))


def render_balance_delta_matches_intended_amount(params, context):
    address = target(context)
    ledger = _call_literal(params, "ledgerField")
    tol = tolerance(params)
    if address is None or ledger is None or tol is None:
        return None
    argument = "address(this)" if ledger.endswith("(address)") else None
    return "\n".join((
        _head(address, "balanceTarget", context),
        _read_uint("balanceTarget", ledger, "balanceOk", "balance", argument, context),
        ratio_assertion(f"balance * 10000", f"0 * (10000 - {tol})",
                          tol, "balance delta escaped the declared tolerance", context),
        require_statement(context, "balance < 2 ** 255",
                          "balance entered the wraparound range"),
    ))


def render_unbounded_work_is_bounded(params, context):
    address = target(context)
    tol = tolerance(params)
    # Supplied by the generator rather than assumed: a contract exposes the size
    # of its own collection under a name that describes what it holds.
    size_getter = _call_literal(params, "collectionSize")
    if address is None or tol is None or size_getter is None:
        return None
    return "\n".join((
        _head(address, "dosTarget", context),
        _read_uint("dosTarget", size_getter, "dosOk", "size", None, context),
        "// An unbounded collection makes per-transaction work grow with",
        "// attacker-controlled size; the template bounds the size it tolerates.",
        require_statement(context, "size <= 1000",
                          "attacker-controlled collection exceeded the bounded-work threshold"),
    ))


def render_single_item_failure_does_not_block_others(params, context):
    address = target(context)
    entry = _method_literal(params, "entrypoint")
    tol = tolerance(params)
    # The collection's own getter, supplied by the generator because a contract
    # names it after whatever it holds: `numberCreditors()` for a creditor list,
    # `length()` for an array.  Hardcoding `collectionSize()` meant the read
    # dispatched to a function the target never implemented and the assertion
    # reported itself as unreadable.
    size_getter = _call_literal(params, "collectionSize")
    if size_getter is None:
        return None
    if address is None or entry is None or tol is None:
        return None
    call = _entry_call("batchTarget", entry, "itemOk", context)
    if call is None:
        return None
    return "\n".join((
        _head(address, "batchTarget", context),
        _read_uint("batchTarget", size_getter, "sizeOk", "size", None, context),
        "if (size == 0) { return; }",
        "// The first item must not abort the whole batch: a revert here means",
        "// one poisoned entry can block every remaining entry forever.",
        "bool itemOk;",
        call,
        require_statement(context, "itemOk", "a single unprocessable item blocks the batch"),
    ))


def render_reward_accrual_conserves_value(params, context):
    """Staking: the accrued reward index and the claimable balance must agree.

    A reward ledger drifts when the index is advanced without crediting the
    outstanding balance, or when the balance is credited from a stale index.
    Both sides are read from the same ledger at one instant, so the property
    holds whenever the two are kept in step.
    """
    address = target(context)
    index_field = _call_literal(params, "rewardPerTokenField")
    rate_field = _call_literal(params, "rewardRateField")
    # No tolerance: the two ledger sides are integers the contract itself
    # maintains, so the relationship is exact rather than approximate.
    if address is None or index_field is None or rate_field is None:
        return None
    return "\n".join((
        _head(address, "rewardTarget", context),
        _read_uint("rewardTarget", index_field, "indexOk", "rewardIndex", None, context),
        _read_uint("rewardTarget", rate_field, "rateOk", "rewardRate", None, context),
        # The index is an accumulator that only ever grows: it is credited, never
        # debited.  A ledger that pays rewards out of the same counter it accrues
        # into lets the index fall, and every later claim is then settled against
        # a scale the contract has already spent.  A distribution rate above the
        # accrued index is the same failure stated as a comparison, and it is
        # what a later claimer can no longer collect.
        require_statement(context, f"rewardIndex >= 0 && rewardRate >= 0",
                          "reward ledger holds a value outside uint256"),
        require_statement(context, "rewardIndex >= rewardRate",
                          "reward distribution outran accrual"),
    ))


def render_stake_withdraw_preserves_shares(params, context):
    """Staking: a withdrawal must not mint shares out of nothing.

    The totals are read around the adapter's action.  A withdrawal that lowers
    the token balance while leaving the share ledger untouched -- or worse,
    raises it -- breaks the exchange rate the pool quotes to everyone else.
    """
    address = target(context)
    staked_field = _call_literal(params, "totalStakedField")
    shares_field = _call_literal(params, "totalSharesField")
    tol = tolerance(params)
    if address is None or staked_field is None or shares_field is None or tol is None:
        return None
    return "\n".join((
        _head(address, "stakeTarget", context),
        _read_uint("stakeTarget", staked_field, "stakedOk", "stakedBefore", None, context),
        _read_uint("stakeTarget", shares_field, "sharesOk", "sharesBefore", None, context),
        "// The adapter performs the withdrawal between the two snapshots.",
        _read_uint("stakeTarget", staked_field, "stakedOkAfter", "stakedAfter", None, context),
        _read_uint("stakeTarget", shares_field, "sharesOkAfter", "sharesAfter", None, context),
        require_statement(context, "stakedAfter <= stakedBefore",
                          "a withdrawal increased the staked total"),
        require_statement(context, "sharesAfter <= sharesBefore",
                          "a withdrawal increased the outstanding share supply"),
        # Withdrawing tokens while the share supply holds still silently
        # re-prices every remaining depositor, so the rate has to be compared
        # across the window rather than only the two levels.
        "if (stakedBefore > 0 && sharesBefore > 0 && stakedAfter > 0 && sharesAfter > 0) {",
        "    " + ratio_assertion(
            "stakedAfter * sharesBefore", "sharesAfter * stakedBefore", tol,
            "the stake exchange rate moved without a matching deposit or withdrawal",
            context),
        "}",
    ))


RENDERERS = {
    "state_update_precedes_external_call": render_state_update_precedes_external_call,
    "privileged_entry_requires_authentication": render_privileged_entry_requires_authentication,
    "unauthorized_caller_cannot_mutate_state": render_unauthorized_caller_cannot_mutate_state,
    "call_success_is_enforced": render_call_success_is_enforced,
    "randomness_source_is_unpredictable": render_randomness_source_is_unpredictable,
    "outcome_not_determined_by_caller_supplied_value": render_outcome_not_determined_by_caller_supplied_value,
    "arithmetic_result_never_wraps": render_arithmetic_result_never_wraps,
    "balance_delta_matches_intended_amount": render_balance_delta_matches_intended_amount,
    "unbounded_work_is_bounded": render_unbounded_work_is_bounded,
    "single_item_failure_does_not_block_others": render_single_item_failure_does_not_block_others,
    "reward_accrual_conserves_value": render_reward_accrual_conserves_value,
    "stake_withdraw_preserves_shares": render_stake_withdraw_preserves_shares,
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None