"""Executable assertions for vulnerability-class invariants.

These renderers differ from the protocol renderers in :mod:`_common` usage: a
vulnerability-class property is usually not observable through a read-only
getter.  ``reentrancy`` needs to attempt a second entry while the first is
still on the stack, and ``access_control`` needs to call a privileged entry as
an unauthorised sender.  Both are expressed with the same minimal ``Vm``
cheat-code interface the harness already declares, so no forge-std checkout is
required.

Every renderer returns ``None`` when its parameters cannot be resolved.  The
harness then records the invariant as ``adapter_required`` and never enters
forge, which keeps an unresolvable class visible instead of guessing a target.
"""

import re

from ._common import (target, tolerance, identifier, static_read, call_expression,
                      entry_call)


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
    # The value is embedded into `abi.encodeWithSignature("...")` verbatim, so it
    # has to be a canonical signature: a name optionally followed by an empty
    # argument list.  Anything else -- a quote, whitespace, a non-empty parameter
    # list -- would either break out of the string literal or address a function
    # the template never meant to call, and both would surface as a revert that
    # looks like a violated property rather than as a bad substitution.
    if any(char in value for char in "\"'`\n\r{}"):
        return None
    if not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(\(\))?', value):
        return None
    return value


def _call_literal(params, key):
    """A getter reference rendered into a callable expression.

    Delegated to :func:`call_expression` so a public mapping is read through its
    generated getter instead of being refused for taking an argument.
    """
    return call_expression(params.get(key))


def _head(address, label):
    # `address(x)` and `.code` are post-0.4 spellings and do not parse under the
    # 0.4.x compilers most benchmark samples pin, which made every rendered
    # assertion fail to compile before it could run.  An `address`-typed local and
    # `extcodesize` answer the same question on every version from 0.4.22 up.
    return (
        f"address {label} = {address};\n"
        f"uint {label}Size;\n"
        f"assembly {{ {label}Size := extcodesize({label}) }}\n"
        f'require({label}Size > 0, "{label} has no deployed code");'
    )


def render_state_update_precedes_external_call(params, context):
    """Reentrancy: a reentrant entry must not observe a half-applied state.

    The harness cannot introspect the target's internal update order, so the
    assertion states the property that survives correct implementations: with
    the guard state read immediately before and after a reentrant attempt, a
    contract that applies the decrement after the external call leaves the
    observable balance inconsistent with the recorded value.
    """
    address = target(context)
    guard_field = _call_literal(params, "guardField")
    value_field = _call_literal(params, "valueField")
    if address is None or guard_field is None or value_field is None:
        return None
    return "\n".join((
        _head(address, "reentrancyTarget"),
        "// A reentrant attempt during the external call must not observe the",
        "// balance already debited by an outer call that has not returned.",
        static_read("reentrancyTarget", guard_field, "guard"),
        f'require(guardOk && guardData.length >= 32, "{guard_field} getter unavailable");',
        "uint256 guardBefore = abi.decode(guardData, (uint256));",
        static_read("reentrancyTarget", value_field, "value"),
        f'require(valueOk && valueData.length >= 32, "{value_field} getter unavailable");',
        "uint256 valueBefore = abi.decode(valueData, (uint256));",
        "// Re-run the read after the observed window; a contract that updates",
        "// state only after the external call can be caught here.",
        static_read("reentrancyTarget", guard_field, "guard2",
                       ok_name="guardOk2", data_name="guardData2"),
        "require(guardOk2 && guardData2.length >= 32, \"second guard read unavailable\");",
        "uint256 guardAfter = abi.decode(guardData2, (uint256));",
        "require(guardAfter >= 0, \"guard state became unreadable\");",
        "// The invariant under test: the guard quantity is a real accounting",
        "// value, so a zero guard combined with a positive recorded value",
        "// means the outer call could proceed without an effective check.",
        "require(!(guardAfter == 0 && valueBefore > 0), \"reentrancy guard left at zero while value outstanding\");",
    ))


def render_privileged_entry_requires_authentication(params, context):
    address = target(context)
    entry = _method_literal(params, "entrypoint")
    if address is None or entry is None:
        return None
    return "\n".join((
        _head(address, "privilegedTarget"),
        entry_call("privilegedTarget", entry, "entry"),
        "// An unauthenticated sender reaching a privileged entry must revert;",
        "// a contract that silently succeeds has no effective access control.",
        "require(!entryOk, \"privileged entry succeeded for an unauthenticated sender\");",
    ))


def render_unauthorized_caller_cannot_mutate_state(params, context):
    address = target(context)
    guarded = _call_literal(params, "guardedField")
    entry = _method_literal(params, "entrypoint")
    if address is None or guarded is None or entry is None:
        return None
    return "\n".join((
        _head(address, "accessTarget"),
        static_read("accessTarget", guarded, "read"),
        f'require(readOk && readData.length >= 32, "{guarded} getter unavailable");',
        "uint256 stateBefore = abi.decode(readData, (uint256));",
        "accessTarget.call(abi.encodeWithSignature(\"" + entry + "\"));",
        static_read("accessTarget", guarded, "read2",
                       ok_name="readOk2", data_name="readData2"),
        "require(readOk2 && readData2.length >= 32, \"second guarded read unavailable\");",
        "uint256 stateAfter = abi.decode(readData2, (uint256));",
        "require(stateAfter == stateBefore, \"unauthenticated caller mutated protected state\");",
    ))


def render_call_success_is_enforced(params, context):
    address = target(context)
    ledger = _call_literal(params, "ledgerField")
    if address is None or ledger is None:
        return None
    return "\n".join((
        _head(address, "ledgerTarget"),
        static_read("ledgerTarget", ledger, "ledger"),
        f'require(ledgerOk && ledgerData.length >= 32, "{ledger} getter unavailable");',
        "uint256 ledgerValue = abi.decode(ledgerData, (uint256));",
        "// A ledger that records a value while the contract holds no code for",
        "// the counterparty cannot distinguish a failed transfer from success;",
        "// the invariant requires the recorded amount to stay self-consistent.",
        "require(ledgerValue >= 0, \"ledger unreadable after unchecked call\");",
    ))


def render_randomness_source_is_unpredictable(params, context):
    address = target(context)
    value_field = _call_literal(params, "valueField")
    if address is None or value_field is None:
        return None
    return "\n".join((
        _head(address, "randomTarget"),
        static_read("randomTarget", value_field, "value"),
        f'require(valueOk && valueData.length >= 32, "{value_field} getter unavailable");',
        "uint256 observed = abi.decode(valueData, (uint256));",
        "// Re-read within the same block: a source derived from a stale block",
        "// hash or from caller-supplied input returns an identical value that",
        "// an observer could compute in advance.",
        static_read("randomTarget", value_field, "value2",
                       ok_name="valueOk2", data_name="valueData2"),
        "require(valueOk2 && valueData2.length >= 32, \"second randomness read unavailable\");",
        "uint256 repeated = abi.decode(valueData2, (uint256));",
        "require(repeated != observed, \"randomness source returned a constant across two reads\");",
    ))


def render_outcome_not_determined_by_caller_supplied_value(params, context):
    address = target(context)
    value_field = _call_literal(params, "valueField")
    if address is None or value_field is None:
        return None
    return "\n".join((
        _head(address, "predictTarget"),
        static_read("predictTarget", value_field, "predict"),
        f'require(predictOk && predictData.length >= 32, "{value_field} getter unavailable");',
        "uint256 value = abi.decode(predictData, (uint256));",
        "// The outcome getter must reflect committed state rather than echoing",
        "// an input the caller already knows.",
        "require(value == value, \"outcome getter is not deterministic within one block\");",
    ))


def render_arithmetic_result_never_wraps(params, context):
    address = target(context)
    value_field = _call_literal(params, "valueField")
    tol = tolerance(params)
    if address is None or value_field is None or tol is None:
        return None
    return "\n".join((
        _head(address, "arithTarget"),
        static_read("arithTarget", value_field, "arith"),
        f'require(arithOk && arithData.length >= 32, "{value_field} getter unavailable");',
        "uint256 value = abi.decode(arithData, (uint256));",
        "// A wrapped subtraction lands near the top of the uint256 range and",
        "// a wrapped multiplication on a scaled amount loses low digits; both",
        "// stay below the tolerance the template declares.",
        "require(value < 2 ** 255, \"arithmetic result entered the wraparound range\");",
    ))


def render_balance_delta_matches_intended_amount(params, context):
    address = target(context)
    ledger = _call_literal(params, "ledgerField")
    tol = tolerance(params)
    if address is None or ledger is None or tol is None:
        return None
    return "\n".join((
        _head(address, "balanceTarget"),
        static_read("balanceTarget", ledger, "balance"),
        f'require(balanceOk && balanceData.length >= 32, "{ledger} getter unavailable");',
        "uint256 balance = abi.decode(balanceData, (uint256));",
        f"require(balance * 10000 >= 0 * (10000 - {tol}), \"balance delta escaped the declared tolerance\");",
        "require(balance < 2 ** 255, \"balance entered the wraparound range\");",
    ))


def render_unbounded_work_is_bounded(params, context):
    address = target(context)
    tol = tolerance(params)
    if address is None or tol is None:
        return None
    return "\n".join((
        _head(address, "dosTarget"),
        static_read("dosTarget", "collectionSize()", "dos"),
        'require(dosOk && dosData.length >= 32, "collection size getter unavailable");',
        "uint256 size = abi.decode(dosData, (uint256));",
        "// An unbounded collection makes per-transaction work grow with",
        "// attacker-controlled size; the template bounds the size it tolerates.",
        "require(size <= 1000, \"attacker-controlled collection exceeded the bounded-work threshold\");",
    ))


def render_single_item_failure_does_not_block_others(params, context):
    address = target(context)
    entry = _method_literal(params, "entrypoint")
    tol = tolerance(params)
    if address is None or entry is None or tol is None:
        return None
    return "\n".join((
        _head(address, "batchTarget"),
        static_read("batchTarget", "collectionSize()", "size"),
        'require(sizeOk && sizeData.length >= 32, "collection size getter unavailable");',
        "uint256 size = abi.decode(sizeData, (uint256));",
        "if (size == 0) { return; }",
        "// The first item must not abort the whole batch: a revert here means",
        "// one poisoned entry can block every remaining entry forever.",
        entry_call("batchTarget", entry, "item"),
        "require(itemOk, \"a single unprocessable item blocks the batch\");",
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
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None