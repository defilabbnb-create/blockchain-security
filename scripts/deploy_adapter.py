"""Generate and optionally run a read-only local Foundry deployment adapter.

The adapter only deploys contracts to a local EVM/fork. It never signs or
broadcasts a transaction to a remote chain. Missing constructor values remain
explicitly unavailable instead of being guessed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

try:
    from keccak import to_checksum_address
except ModuleNotFoundError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from keccak import to_checksum_address


def _source_digest(sources: dict[str, Any]) -> str:
    import hashlib

    value = {name: entry.get("content") for name, entry in sorted(sources.items())}
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":")).encode()).hexdigest()


def _target(bundle: dict[str, Any]) -> tuple[str, str] | None:
    metadata = bundle.get("metadata") if isinstance(bundle.get("metadata"), dict) else {}
    settings = metadata.get("settings") if isinstance(metadata.get("settings"), dict) else {}
    targets = settings.get("compilationTarget")
    if not isinstance(targets, dict) or len(targets) != 1:
        return None
    source, contract = next(iter(targets.items()))
    if not isinstance(source, str) or not isinstance(contract, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", contract):
        return None
    return source, contract


def _abi(bundle: dict[str, Any], contract: str) -> list[dict[str, Any]]:
    candidates = [bundle.get("abi"), bundle.get("contractAbi")]
    contracts = bundle.get("contracts")
    if isinstance(contracts, dict):
        candidate = contracts.get(contract)
        if isinstance(candidate, dict):
            candidates.extend((candidate.get("abi"), candidate.get("metadata", {}).get("abi") if isinstance(candidate.get("metadata"), dict) else None))
    metadata = bundle.get("metadata")
    if isinstance(metadata, dict):
        candidates.append(metadata.get("abi"))
    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


def _constructor(abi: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((item for item in abi if item.get("type") == "constructor"), None)


def _solidity_literal(value: Any, typ: str, internal_type: str = "") -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        if typ == "address":
            if not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
                raise ValueError("invalid address constructor argument")
            # Solidity 0.8 rejects an address literal whose case does not match
            # the EIP-55 checksum, and the recovered argument is the raw hex
            # from the creation transaction, which carries no checksum.  The
            # checksummed form is the same address, so the deployment is the
            # same contract; the error it prevents is a compile failure, not a
            # different address.
            literal = to_checksum_address(value)
            # A parameter declared as a contract type needs an explicit cast:
            # the ABI type is `address`, but the Solidity type is the interface
            # or contract it names, and Solidity does not convert implicitly.
            contract = _contract_type(internal_type)
            return f"{contract}({literal})" if contract else literal
        if typ.startswith("bytes") or typ == "string":
            return json.dumps(value)
        if re.fullmatch(r"(?:u?int)(?:[0-9]{0,3})", typ or "") and re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", value):
            return value
    if isinstance(value, list):
        return "[" + ", ".join(_solidity_literal(item, typ.rstrip("[]")) for item in value) + "]"
    raise ValueError(f"unsupported constructor value for {typ or 'unknown'}")


def _contract_type(internal_type: str) -> str:
    """The contract or interface name a constructor parameter is declared with.

    The ABI type of such a parameter is `address`, and the declaration carries
    the concrete type in `internalType` as `contract IRegistryV1`.  Solidity
    refuses to pass a plain address where a contract type is expected, so the
    literal has to be cast to the declared name.
    """
    text = str(internal_type or "").strip()
    if not text.startswith("contract "):
        return ""
    name = text[len("contract "):].strip()
    return name if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name) else ""


def _constructor_values(constructor: dict[str, Any], provided: Any) -> tuple[list[str], list[str]]:
    inputs = constructor.get("inputs") if isinstance(constructor.get("inputs"), list) else []
    provided = provided if isinstance(provided, (list, dict)) else None
    literals = []
    missing = []
    for index, item in enumerate(inputs):
        name = item.get("name") or f"arg{index}"
        value = provided.get(name) if isinstance(provided, dict) else (provided[index] if isinstance(provided, list) and index < len(provided) else None)
        if value is None:
            missing.append(name)
            continue
        literals.append(_solidity_literal(value, str(item.get("type") or ""), str(item.get("internalType") or "")))
    return literals, missing


def generate_deployment(bundle: dict[str, Any], output_dir: str | Path, *, constructor_args: Any = None) -> dict[str, Any]:
    if not isinstance(bundle, dict) or not isinstance(bundle.get("sources"), dict):
        raise ValueError("verified source bundle requires sources")
    target = _target(bundle)
    if target is None:
        return {"schemaVersion": 1, "state": "adapter_required", "reason": "compilation_target_missing_or_ambiguous", "missing": ["compilationTarget"]}
    source_unit, contract = target
    abi = _abi(bundle, contract)
    constructor = _constructor(abi)
    literals, missing = _constructor_values(constructor, constructor_args) if constructor else ([], [])
    if constructor and missing:
        return {"schemaVersion": 1, "state": "adapter_required", "contract": contract, "sourceUnit": source_unit,
                "reason": "constructor_arguments_missing", "missing": missing}
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("deployment output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    source_path = Path(source_unit)
    if source_path.is_absolute() or ".." in source_path.parts:
        raise ValueError("source unit path is unsafe")
    for name, entry in bundle["sources"].items():
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            raise ValueError("verified source entries must contain content")
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("source unit path is unsafe")
        destination = output / "src" / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(entry["content"], encoding="utf-8")
    args = ", ".join(literals)
    script = f'''// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;
import "forge-std/Script.sol";
import "../src/{source_unit}";

contract Deploy is Script {{
    function run() external returns (address deployed) {{
        vm.startBroadcast();
        deployed = address(new {contract}({args}));
        vm.stopBroadcast();
    }}
}}
'''
    (output / "script").mkdir(exist_ok=True)
    (output / "script" / "Deploy.s.sol").write_text(script, encoding="utf-8")
    manifest = {"schemaVersion": 1, "state": "ready", "contract": contract, "sourceUnit": source_unit,
                "sourceBundleSha256": _source_digest(bundle["sources"]), "constructorArgs": constructor_args or [],
                "script": "script/Deploy.s.sol", "target": None}
    (output / "deployment.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def run_deployment(output_dir: str | Path, *, forge: str | Path = "forge", timeout: float = 120) -> dict[str, Any]:
    output = Path(output_dir).resolve()
    manifest_path = output / "deployment.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("state") != "ready":
        return manifest
    command = [str(forge), "script", "script/Deploy.s.sol", "--root", str(output), "--json"]
    try:
        completed = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as error:
        manifest.update({"state": "unavailable", "reason": "forge_not_found", "error": str(error)})
    except subprocess.TimeoutExpired as error:
        manifest.update({"state": "failed", "reason": "deployment_timeout", "error": str(error)})
    else:
        if completed.returncode != 0:
            manifest.update({"state": "failed", "reason": "forge_deployment_failed", "error": (completed.stderr or completed.stdout or "").strip()})
        else:
            manifest.update({"state": "deployed", "output": (completed.stdout or "").strip()})
            match = re.search(r"0x[0-9a-fA-F]{40}", completed.stdout or "")
            if match:
                manifest["target"] = match.group(0)
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, manifest_path)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--constructor-args", type=Path)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--forge", default="forge")
    args = parser.parse_args(argv)
    constructor_args = json.loads(args.constructor_args.read_text(encoding="utf-8")) if args.constructor_args else None
    result = generate_deployment(json.loads(args.bundle.read_text(encoding="utf-8")), args.output, constructor_args=constructor_args)
    if args.run and result.get("state") == "ready":
        result = run_deployment(args.output, forge=args.forge)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("state") in {"ready", "deployed", "adapter_required", "unavailable"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
