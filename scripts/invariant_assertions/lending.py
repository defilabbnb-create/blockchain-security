"""Executable Solidity assertion snippets for lending pools."""

from ._common import guard, read_expr, ratio_assertion


def render_health_factor_monotonic_on_borrow(params, context):
    checked = guard(params, context, "riskField")
    if checked is None:
        return None
    address, _, (risk,) = checked
    return "\n".join((
        read_expr(address, risk, "healthBefore"),
        "// The adapter borrows against the same account between snapshots.",
        read_expr(address, risk, "healthAfter"),
        "require(healthAfter <= healthBefore, \"borrow increased the account health factor\");",
    ))


def render_liquidation_does_not_create_bad_debt(params, context):
    bad_debt = params.get("badDebtField") or params.get("debtField")
    if not isinstance(bad_debt, str):
        return None
    local = dict(params)
    local["badDebtField"] = bad_debt
    checked = guard(local, context, "badDebtField")
    if checked is None:
        return None
    address, tolerance_bps, (field,) = checked
    return "\n".join((
        read_expr(address, field, "badDebtBefore"),
        "// The adapter liquidates the selected account between snapshots.",
        read_expr(address, field, "badDebtAfter"),
        f"require(badDebtAfter * 10000 <= badDebtBefore * (10000 + {tolerance_bps}), \"liquidation created unrecorded bad debt\");",
    ))


def render_interest_accrual_conserves_value(params, context):
    checked = guard(params, context, "debtField", "supplyField")
    if checked is None:
        return None
    address, tolerance_bps, (debt, supply) = checked
    return "\n".join((
        read_expr(address, debt, "debtBefore"),
        read_expr(address, supply, "supplyBefore"),
        "// The adapter accrues interest between snapshots.",
        read_expr(address, debt, "debtAfter"),
        read_expr(address, supply, "supplyAfter"),
        f"require(debtAfter * 10000 + supplyAfter * 10000 >= debtBefore * 10000 + supplyBefore * (10000 - {tolerance_bps}), \"interest accrual violated value conservation\");",
    ))


RENDERERS = {
    "health_factor_monotonic_on_borrow": render_health_factor_monotonic_on_borrow,
    "liquidation_does_not_create_bad_debt": render_liquidation_does_not_create_bad_debt,
    "interest_accrual_conserves_value": render_interest_accrual_conserves_value,
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None
