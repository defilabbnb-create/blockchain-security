"""Executable snippets for invariants spanning an external dependency."""

from ._common import target, tolerance, identifier, read_value, require_statement


def _dependency(context):
    if not isinstance(context, dict):
        return None
    value = context.get("dependency_addr_expr") or context.get("oracle_addr_expr")
    return value.strip() if isinstance(value, str) and value.strip() else None


def render_oracle_assumption_holds(params, context):
    dependency = _dependency(context)
    target_expr = target(context)
    oracle_field = identifier(params, "oracleField")
    max_value = params.get("maxOracleValue")
    tol = tolerance(params)
    if dependency is None or target_expr is None or oracle_field is None or not isinstance(max_value, int) or max_value < 0 or tol is None:
        return None
    return "\n".join((
        # `oracleValueOk` guards the read, so it has to be checked rather than
        # declared: the line used to be a quoted string, which emitted no check
        # at all and let the assertion pass on an oracle it could not read.
        read_value(dependency, f"{oracle_field}()", "oracleValueOk", "oracleValue"),
        require_statement(context, "oracleValueOk", "oracle getter unavailable"),
        require_statement(context, f"oracleValue <= {max_value}",
                          "oracle returned a value above the protocol assumption"),
        # `address(...)` and `.code` are post-0.4 spellings; an address-typed local
        # and `extcodesize` state the same check on every version from 0.4.22 up.
        # The size lives in a block because the oracle value is still live above
        # it, and the 0.4.x codegen has only 16 slots to work with.
        "{",
        "    address oracleTarget = " + str(target_expr) + ";",
        "    uint256 oracleTargetSize;",
        "    assembly { oracleTargetSize := extcodesize(oracleTarget) }",
        "    " + require_statement(context, "oracleTargetSize > 0",
                                  "oracle target has no deployed code"),
        "}",
    ))


def render_dependency_return_bounds(params, context):
    dependency = _dependency(context)
    return_type = params.get("returnType", "uint256")
    field = identifier(params, "dependencyField")
    lower = params.get("minReturn", 0)
    upper = params.get("maxReturn")
    if dependency is None or field is None or return_type != "uint256" or not isinstance(lower, int) or lower < 0 or not isinstance(upper, int) or upper < lower:
        return None
    return "\n".join((
        read_value(dependency, f"{field}()", "dependencyValueOk", "dependencyValue"),
        require_statement(context, "dependencyValueOk", "dependency getter unavailable"),
        require_statement(context,
                          f"dependencyValue >= {lower} && dependencyValue <= {upper}",
                          "dependency return value is outside the caller bounds"),
    ))


RENDERERS = {
    "oracle_assumption_holds": render_oracle_assumption_holds,
    "dependency_return_bounds": render_dependency_return_bounds,
}


def render(params, context):
    template = params.get("template") if isinstance(params, dict) else None
    renderer = RENDERERS.get(template)
    return renderer(params, context) if renderer else None
