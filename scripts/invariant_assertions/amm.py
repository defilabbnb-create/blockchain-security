"""Executable Solidity assertion snippets for constant-product AMMs."""

from ._common import guard, read_expr


def render_k_never_decreases(params, context):
    checked = guard(params, context, "reserve0Field", "reserve1Field")
    if checked is None:
        return None
    address, tolerance_bps, (reserve0, reserve1) = checked
    return "\n".join((
        read_expr(address, reserve0, "reserve0Before"),
        read_expr(address, reserve1, "reserve1Before"),
        "// The adapter executes a swap between snapshots.",
        read_expr(address, reserve0, "reserve0After"),
        read_expr(address, reserve1, "reserve1After"),
        f"require(reserve0After * reserve1After * 10000 >= reserve0Before * reserve1Before * (10000 - {tolerance_bps}), \"constant product k decreased\");",
    ))


def render_fee_conserved(params, context):
    checked = guard(params, context, "reserve0Field", "reserve1Field", "feeField")
    if checked is None:
        return None
    address, tolerance_bps, (reserve0, reserve1, fee) = checked
    return "\n".join((
        read_expr(address, reserve0, "feeReserve0Before"),
        read_expr(address, reserve1, "feeReserve1Before"),
        read_expr(address, fee, "feeBefore"),
        "// The adapter executes a swap between snapshots.",
        read_expr(address, reserve0, "feeReserve0After"),
        read_expr(address, reserve1, "feeReserve1After"),
        read_expr(address, fee, "feeAfter"),
        f"require(feeAfter * 10000 + {tolerance_bps} >= feeBefore * 10000, \"AMM fee ledger decreased unexpectedly\");",
    ))


RENDERERS = {
    "k_never_decreases": render_k_never_decreases,
    "fee_conserved": render_fee_conserved,
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None
