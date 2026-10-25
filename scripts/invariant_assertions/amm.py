"""Executable Solidity assertion snippets for constant-product AMMs.

Both properties are *transition* properties: the constant product is compared
across a swap, and the fee ledger is compared across a swap.  A transition
property needs something to perform the transition between the two readings.

The harness marks the place with a comment line, and the caller may supply an
adapter that performs the action there.  The reverse-fixture gate does exactly
that -- it substitutes a real ``swap`` call for the marker and then requires
the same assertion to pass on a correct pool and fail on a violating one --
which is what establishes that these two assertions have discriminating power
at all.  Without a supplied adapter the marker stays a comment, the two
readings are two reads of an unchanged pool, and the comparison is decided
before any protocol action happened:

    reserve0After * reserve1After * 10000 >= reserve0Before * reserve1Before * 10000

with ``reserve0After == reserve0Before`` and ``reserve1After == reserve1Before``
holding on every contract, so the inequality held on every contract.  A verdict
of "passed" from such a comparison is evidence about the harness, not about the
pool, and a pool that genuinely loses reserve value through a swap would still
be recorded as passing.

So these renderers refuse to produce a body unless the caller supplies an
adapter for the template.  The refusal is what the harness records as
"adapter required": the assertion is *not executed*, with the reason that a
swap adapter is missing, instead of producing a passing verdict that measures
nothing.  A missed detection is the honest outcome here -- a fabricated pass is
worse than an absence, because it makes an unmeasured property look measured.
"""

from ._common import guard, read_expr, ratio_assertion, require_statement

# The marker the harness looks for when substituting an adapter.  The reverse
# fixture gate searches for the same prefix, so the two stay in step: one
# spelling of "put the action here".
ADAPTER_MARKER = "// The adapter"


def _adapter_missing(template, params, context):
    """Whether the caller supplied the adapter this template needs.

    The context carries the adapters the caller resolved for this harness.
    A template with no adapter renders nothing, which the harness records as
    an assertion that was not executed.
    """
    adapters = context.get("adapters") if isinstance(context, dict) else None
    if not isinstance(adapters, dict):
        return True
    action = adapters.get(template)
    if not isinstance(action, str) or not action.strip():
        return True
    return False


def render_k_never_decreases(params, context):
    """Compare the constant product across a swap, if a swap adapter exists."""
    if _adapter_missing("k_never_decreases", params, context):
        return None
    checked = guard(params, context, "reserve0Field", "reserve1Field")
    if checked is None:
        return None
    address, tolerance_bps, (reserve0, reserve1) = checked
    return "\n".join((
        read_expr(address, reserve0, "reserve0Before", context),
        read_expr(address, reserve1, "reserve1Before", context),
        "// The adapter executes a swap between snapshots.",
        read_expr(address, reserve0, "reserve0After", context),
        read_expr(address, reserve1, "reserve1After", context),
        ratio_assertion("reserve0After * reserve1After", "reserve0Before * reserve1Before",
                      tolerance_bps, "constant product k decreased", context),
    ))


def render_fee_conserved(params, context):
    """Compare the fee ledger across a swap, if a swap adapter exists."""
    if _adapter_missing("fee_conserved", params, context):
        return None
    checked = guard(params, context, "reserve0Field", "reserve1Field", "feeField")
    if checked is None:
        return None
    address, tolerance_bps, (reserve0, reserve1, fee) = checked
    return "\n".join((
        read_expr(address, reserve0, "feeReserve0Before", context),
        read_expr(address, reserve1, "feeReserve1Before", context),
        read_expr(address, fee, "feeBefore", context),
        "// The adapter executes a swap between snapshots.",
        read_expr(address, reserve0, "feeReserve0After", context),
        read_expr(address, reserve1, "feeReserve1After", context),
        read_expr(address, fee, "feeAfter", context),
        require_statement(context,
                          f"feeAfter * 10000 + {tolerance_bps} >= feeBefore * 10000",
                          "AMM fee ledger decreased unexpectedly"),
    ))


RENDERERS = {
    "k_never_decreases": render_k_never_decreases,
    "fee_conserved": render_fee_conserved,
}

# The reason each template is not executable without an adapter, recorded
# verbatim in the harness manifest so that an unmeasured sample says *why* it
# was unmeasured.
UNAVAILABLE_REASONS = {
    "k_never_decreases": "constant_product_comparison_requires_a_swap_between_the_two_reserve_readings",
    "fee_conserved": "fee_ledger_comparison_requires_a_swap_between_the_two_fee_readings",
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None
