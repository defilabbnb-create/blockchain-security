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


def read_expr(address, field, label):
    return (
        f"uint256 {label}; {{ (bool ok, bytes memory data) = address({address}).staticcall("
        f'abi.encodeWithSignature(\"{field}()\")); '
        f'require(ok && data.length >= 32, \"{label} getter unavailable\"); '
        f"{label} = abi.decode(data, (uint256)); }}"
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
