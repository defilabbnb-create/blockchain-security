"""Resolve the state transition a transition-property assertion needs.

A property like "the constant product does not decrease across a swap" is
decided by comparing two readings with a protocol action in between.  The
assertion layer knows how to read the pool's state and how to compare the two
readings, but it cannot invent the action: the action is a call into the
contract under test, and which call that is depends on that contract's own
interface.

This module resolves the action from evidence the compilation already
produced -- the unified IR's function list and the ABI the compiler reported.
The call it emits is a low-level call carrying the ABI-encoded arguments, so
it dispatches to exactly the function the interface names and nothing else.
The arguments are placeholders: the property being checked is a comparison
across the transition, and the comparison has to be about the transition the
contract performs rather than about one particular argument value.  A
placeholder that the contract rejects would make the action revert, and a
reverting action leaves the two readings equal -- the same defect the
un-adopted assertion had.  So an action whose call does not succeed is
reported as a failure of the action rather than as a violation of the
property: the emitted call skips the test instead of asserting on it, so forge
records the measurement as skipped rather than failed.

Nothing here guesses a function name.  A template that needs an action and
finds no matching entry point in the evidence is left without one, and the
assertion is recorded as not executed.
"""

from __future__ import annotations

import re
from typing import Any

# The action each transition property needs, by the name of the protocol
# operation.  The keys are matched against the function names the evidence
# reports, lowercased.
ACTION_REQUIREMENTS = {
    "k_never_decreases": "swap",
    "fee_conserved": "swap",
    "share_price_monotonic": "deposit",
    "withdraw_preserves_remaining_value": "withdraw",
    "donation_does_not_change_ledger": "donate",
    "first_deposit_no_inflation": "deposit",
    "health_factor_monotonic_on_borrow": "borrow",
    "liquidation_does_not_create_bad_debt": "liquidate",
    "interest_accrual_conserves_value": "accrue",
    "stake_withdraw_preserves_shares": "withdraw",
}

# Argument types a low-level call can carry.  A parameter of any other type
# cannot be filled with a placeholder, so a function that takes one is not
# usable as an action.
#
# The numeric placeholders are Solidity expressions rather than literals, and
# they are resolved inside the harness where the contract's own state is
# readable.  A literal cannot work: `deposit(0)` is refused by every vault that
# checks its input, and `swap(0,0)` leaves the reserves where they were, so the
# two readings the property compares are equal and the check passes without
# having measured anything.  A numeric literal large enough to be accepted is
# just as bad in the other direction -- against a vault whose share price has
# risen, a fixed amount can mint a single wei of shares.  The call succeeds,
# nothing is recorded as failed, and the assertion compares two identical
# readings while appearing to have run.  Reading the amount from the contract
# scales it to whatever the ledger is currently worth, which is the only
# spelling that survives both edges.
_PLACEHOLDER = {
    "uint256": "_adapterAmount(target)",
    "uint128": "_adapterAmount(target)",
    "uint96": "_adapterAmount(target)",
    "uint64": "_adapterAmount(target)",
    "uint32": "_adapterAmount(target)",
    "uint16": "_adapterAmount(target)",
    "uint8": "_adapterAmount(target)",
    "uint": "_adapterAmount(target)",
    "int256": "_adapterAmount(target)",
    "int128": "_adapterAmount(target)",
    "address": "address(this)",
    "bool": "false",
    "bytes32": "bytes32(0)",
}

_SIGNATURE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^()]*)\)")


def _split_types(text: str) -> list[str]:
    parts = []
    for part in text.split(","):
        value = part.strip()
        if value:
            parts.append(value)
    return parts


def _normalise(type_name: str) -> str:
    """The canonical Solidity spelling of a parameter type.

    The IR and the ABI spell the same type differently: the IR carries the
    declaration's own text, which may name the parameter and give a data
    location, and the ABI carries the canonical form.  Only the canonical form
    can be placed in a call expression, so the parameter name and the storage
    keyword are removed.  Leaving a parameter name in place would splice it
    onto its type -- `uint256 input` became `uint256input`, which names no type
    at all and would make every such entry point look unusable.
    """
    value = type_name.strip()
    # A data location and a parameter name both sit after the type in a
    # declaration; the type itself is the first word of what remains.
    value = re.sub(r"\b(memory|storage|calldata)\b", " ", value)
    value = value.strip().split()
    return _normalise_type_head(value[0]) if value else ""


def _normalise_type_head(head: str) -> str:
    """Reduce a type's leading token to its canonical spelling.

    ``contract IRegistryV1`` and ``interface IRegistryV1`` are ABI types of
    ``address``, and the canonical spelling of the declared name is what the
    call expression needs in order to cast.  An array suffix is kept, since
    `uint256[]` names a type the adapter cannot carry and has to stay visible
    as such rather than being flattened to `uint256`.
    """
    value = re.sub(r"\s+", "", head)
    for prefix in ("contract ", "interface ", "enum "):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _placeholder_for(type_name: str) -> str | None:
    canonical = _normalise(type_name)
    if canonical in _PLACEHOLDER:
        return _PLACEHOLDER[canonical]
    # Any other fixed-width integer names the same kind of amount, including
    # the widths the table does not spell out and the aliases (`uint`/`int`).
    if canonical.startswith("uint") and canonical[4:].isdigit():
        return _PLACEHOLDER["uint256"]
    if canonical.startswith("int") and canonical[3:].isdigit():
        return _PLACEHOLDER["int256"]
    return None


def _function_entries(evidence: list[dict[str, Any]]) -> list[tuple[str, list[str]]]:
    """The callable entries the evidence reports, as (name, parameter types)."""
    entries: list[tuple[str, list[str]]] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        raw = item.get("name")
        if not isinstance(raw, str) or not raw.strip():
            continue
        # The IR qualifies the name as `Contract::Contract.swap(uint256,uint256)`.
        # The contract prefix is not part of the selector, so it is removed.
        text = raw
        if "::" in text:
            text = text.rsplit("::", 1)[1]
        match = _SIGNATURE.search(text)
        if match is None:
            entries.append((text.strip(), []))
            continue
        name = match.group(1)
        parameters = [_normalise(part) for part in _split_types(match.group(2))]
        entries.append((name, parameters))
    return entries


def _call_expression(name: str, parameters: list[str]) -> str | None:
    """The low-level call that performs the action, or None if it cannot carry one."""
    placeholders = []
    for parameter in parameters:
        value = _placeholder_for(parameter)
        if value is None:
            return None
        placeholders.append(value)
    signature = f"{name}({','.join(parameters)})"
    encoded = ", ".join(placeholders)
    # A call that reverts is not a violation of the property, it is a failure to
    # measure it.  The two are told apart by what forge reports.  `require` on
    # the success flag aborts the test, forge prints FAIL, and a FAIL whose output
    # names neither a compilation problem nor a missing target is recorded as a
    # violation -- so an action the contract rejected was reported as a protocol
    # violation.  That is a false positive, on the one axis the downstream
    # confirmation work treats as evidence.
    #
    # `vm.skip` gives forge a third outcome and forge carries it natively: the
    # test is reported SKIP rather than PASS or FAIL.  Stopping here keeps a
    # rejected action out of the violation bucket, and because the body after
    # this line never runs, nothing is claimed about the property either.
    #
    # A skip is not free.  Forge exits 0 when every test skipped, and an exit 0
    # reads as PASS to anything watching only the return code, which would turn
    # the false positive into a silent false negative.  The caller therefore has
    # to read the per-test outcome too, which `dynamic_runner` now does.
    return (f'{{ (bool ok,) = target.call(abi.encodeWithSignature("{signature}", {encoded})); '
            f'if (!ok) {{ _skipUnavailable(); }} }}')


def resolve_adapters(templates, evidence, *, context=None):
    """Resolve the action each requested template needs from the evidence.

    ``templates`` are the template names that are about to be rendered.
    ``evidence`` is the list of function records the unified IR and the ABI
    produced, each carrying a name and, when known, a parameter list.

    The returned mapping is keyed by template name and holds the Solidity
    action.  A template with no matching entry point is absent from the
    mapping, which is what makes the renderer decline.
    """
    entries = _function_entries(evidence)
    if not entries:
        return {}
    resolved: dict[str, str] = {}
    for template in templates:
        wanted = ACTION_REQUIREMENTS.get(template)
        if wanted is None:
            continue
        for name, parameters in entries:
            if name.lower() != wanted:
                continue
            call = _call_expression(name, parameters)
            if call is not None:
                resolved[template] = call
                break
    return resolved
