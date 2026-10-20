"""Executable Solidity assertion snippets for ERC-4626 style vaults."""

from ._common import guard, read_expr, ratio_assertion


def render_share_price_monotonic(params, context):
    checked = guard(params, context, "assetsField", "sharesField")
    if checked is None:
        return None
    address, tolerance_bps, (assets, shares) = checked
    return "\n".join((
        read_expr(address, assets, "assetsBefore"),
        read_expr(address, shares, "sharesBefore"),
        "// The adapter performs the protocol action between the two snapshots.",
        read_expr(address, assets, "assetsAfter"),
        read_expr(address, shares, "sharesAfter"),
        f"if (assetsBefore > 0 && sharesBefore > 0 && sharesAfter > 0) {{ {ratio_assertion('assetsAfter * sharesBefore', 'assetsBefore * sharesAfter', tolerance_bps, 'share price unexpectedly decreased beyond tolerance')} }}",
    ))


def render_withdraw_preserves_remaining_value(params, context):
    checked = guard(params, context, "assetsField", "sharesField")
    if checked is None:
        return None
    address, tolerance_bps, (assets, shares) = checked
    return "\n".join((
        read_expr(address, assets, "assetsBefore"),
        read_expr(address, shares, "sharesBefore"),
        "// The adapter performs the withdrawal between the two snapshots.",
        read_expr(address, assets, "assetsAfter"),
        read_expr(address, shares, "sharesAfter"),
        f"require(sharesAfter <= sharesBefore, \"withdrawal increased total shares\");",
        f"if (sharesBefore > 0 && sharesAfter > 0) {{ {ratio_assertion('assetsAfter * sharesBefore', 'assetsBefore * sharesAfter', tolerance_bps, 'withdrawal did not preserve remaining share value')} }}",
    ))


def render_donation_does_not_change_ledger(params, context):
    checked = guard(params, context, "assetsField", "sharesField")
    if checked is None:
        return None
    address, _, (assets, shares) = checked
    return "\n".join((
        read_expr(address, assets, "assetsBefore"),
        read_expr(address, shares, "supplyBefore"),
        "// The adapter sends a direct donation between the two snapshots.",
        read_expr(address, assets, "assetsAfter"),
        read_expr(address, shares, "supplyAfter"),
        "require(supplyAfter == supplyBefore, \"direct donation changed share supply ledger\");",
        "require(assetsAfter >= assetsBefore, \"direct donation decreased recorded assets\");",
    ))


def render_first_deposit_no_inflation(params, context):
    checked = guard(params, context, "assetsField", "sharesField")
    if checked is None:
        return None
    address, tolerance_bps, (assets, shares) = checked
    return "\n".join((
        read_expr(address, assets, "assetsBefore"),
        read_expr(address, shares, "sharesBefore"),
        "// The adapter executes the first deposit and records the resulting shares.",
        read_expr(address, assets, "assetsAfter"),
        read_expr(address, shares, "sharesAfter"),
        f"if (sharesBefore == 0 && assetsAfter > 0) {{ {ratio_assertion('assetsAfter * sharesAfter', 'assetsBefore + 1', tolerance_bps, 'first deposit created an inflated share price')} }}",
    ))


def render_rounding_direction_correct(params, context):
    checked = guard(params, context, "assetsField", "sharesField")
    if checked is None:
        return None
    address, _, (assets, shares) = checked
    return "\n".join((
        read_expr(address, assets, "roundingAssets"),
        read_expr(address, shares, "roundingShares"),
        "require(roundingAssets == 0 || roundingShares == 0 || roundingAssets * roundingShares >= 0, \"rounding direction could not be established\");",
    ))


RENDERERS = {
    "share_price_monotonic": render_share_price_monotonic,
    "withdraw_preserves_remaining_value": render_withdraw_preserves_remaining_value,
    "donation_does_not_change_ledger": render_donation_does_not_change_ledger,
    "first_deposit_no_inflation": render_first_deposit_no_inflation,
    "rounding_direction_correct": render_rounding_direction_correct,
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None
