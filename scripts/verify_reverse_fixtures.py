#!/usr/bin/env python3
"""Run the assertion fixtures against both correct and violating contracts.

The gate intentionally executes the same generated Solidity assertion source for
both variants. A passing correct fixture and a failing violating fixture are
required; compiler errors, missing metadata, and unavailable Forge are failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "assertions"

sys.path.insert(0, str(ROOT / "scripts"))
from invariant_assertions import load_renderers  # noqa: E402
import harness_gen  # noqa: E402


def _harness_helpers() -> str:
    """The selector and call primitives, taken from the harness that owns them.

    The fixture gate renders the same assertion bodies as the benchmark harness,
    so it needs the same helpers.  When they lived only inside the harness
    template, the gate compiled against a stale hand-written copy and every
    fixture failed with "Undeclared identifier: _readWord" -- the fixtures stopped
    testing the assertions at all, and the gate reported a compile error rather
    than a missing helper.  Generating the harness and lifting the helper block
    out of it keeps a single spelling of both.
    """
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        invariants = {"schemaVersion": 1, "sourceSha256": None,
                      "invariants": [{"invariantId": "a" * 64,
                                      "template": "share_price_monotonic",
                                      "params": {"assetsField": "totalAssets",
                                                 "sharesField": "totalSupply",
                                                 "toleranceBps": 0}}]}
        source = "pragma solidity >=0.8.19;\ncontract Target { }\n"
        bundle = {"sources": {"Target.sol": {"content": source}},
                  "metadata": {"settings": {"compilationTarget": {"Target.sol": "Target"}}},
                  "abi": []}
        manifest = harness_gen.generate_harness(invariants, bundle, root,
                                                compiler_version="0.8.19")
        tests = [row for row in manifest["tests"] if row.get("path")]
        text = (root / tests[0]["path"]).read_text(encoding="utf-8")

    start = text.index("    // Selector + calldata, assembled by hand.")
    end = text.index("    // The assertion body runs in its own frame")
    return text[start:end]


def _source_file(directory: Path) -> Path:
    files = sorted(directory.glob("*.sol"))
    if len(files) != 1:
        raise ValueError(f"{directory}: expected exactly one Solidity source")
    return files[0]


def _contract_name(source: str) -> str:
    match = re.search(r"\bcontract\s+([A-Za-z_$][A-Za-z0-9_$]*)\b", source)
    if not match:
        raise ValueError("fixture source does not declare a contract")
    return match.group(1)


def _call(signature: str, *args: object) -> str:
    """The gate's own action, carrying the values the fixture was written for.

    This is deliberately not the production spelling.  `invariant_adapters`
    fills placeholders and skips the test when the contract declines the call,
    because there the arguments are guesses and a rejected call is a failed
    measurement.  Here the arguments come from the fixture, which is a contract
    written to accept them, so a rejected call is a broken fixture or a broken
    template rather than an unusable measurement -- and the gate wants to say so
    loudly instead of counting the fixture as skipped.  `require` aborts the test
    and forge reports FAIL, which is the signal this gate reads.
    """
    encoded = ", ".join(str(value) for value in args)
    return f"{{ (bool ok,) = target.call(abi.encodeWithSignature(\"{signature}\", {encoded})); require(ok, \"fixture adapter call failed\"); }}"


def _adapter(fixture: str, template: str) -> tuple[str, str]:
    """Return setup and the state transition inserted into the assertion."""
    if fixture == "erc4626":
        return _call("deposit(uint256)", 100), _call("withdraw(uint256)", 1)
    if fixture == "erc4626-donation":
        return _call("deposit(uint256)", 100), _call("donate(uint256)", 100)
    if fixture == "erc4626-rounding":
        return "", ""
    if fixture == "amm":
        return "", _call("swap(uint256,uint256)", 100, 90)
    if fixture == "lending" and template == "health_factor_monotonic_on_borrow":
        return _call("depositCollateral(uint256)", 100), _call("borrow(uint256)", 10)
    if fixture == "lending" and template == "interest_accrual_conserves_value":
        return _call("depositCollateral(uint256)", 100) + _call("borrow(uint256)", 10), _call("accrue(uint256)", 5)
    if fixture == "lending-liquidation":
        account = "address(0x0000000000000000000000000000000000000001)"
        return _call("seed(address,uint256,uint256)", account, 100, 60), _call("liquidate(address,uint256)", account, 20)
    raise ValueError(f"no fixture adapter for {fixture}/{template}")


def _render_assertion(fixture: str, template: str, params: dict) -> tuple[str, str]:
    renderers = load_renderers()
    renderer = renderers.get(template)
    if renderer is None:
        raise ValueError(f"no registered renderer for {template}")
    setup, action = _adapter(fixture, template)
    # A renderer that compares state across a transition refuses to produce a
    # body until it is told which action performs that transition.  The gate
    # knows the action, so it passes it in; the renderer then emits the body
    # with the marker in place, and the substitution below replaces the marker
    # with the action.  The renderer declining without an adapter is the
    # intended behaviour, not a failure -- the gate is what supplies one.
    context = {"contract_name": "Target", "target_addr_expr": "target",
               "adapters": {template: action} if action else {}}
    body = renderer(params, context)
    if not isinstance(body, str) or not body.strip():
        raise ValueError(f"renderer returned adapter_required for {fixture}/{template}")
    marker = "// The adapter"
    if action:
        positions = [match.start() for match in re.finditer(re.escape(marker), body)]
        if len(positions) != 1:
            raise ValueError(f"{fixture}/{template}: assertion has no unique adapter marker")
        body = body.replace(body[positions[0]:body.find("\n", positions[0])], action, 1)
    return setup, body


def _poc_source(import_name: str) -> tuple[str, str]:
    body = """        Reentrant attacker = new Reentrant();
        vm.deal(address(attacker), 3 ether);
        (bool ok,) = address(attacker).call(abi.encodeWithSignature(\"attack()\"));
        require(!ok, \"reentrant withdrawal succeeded\");"""
    test_source = """import \"../src/%s\";
// `skip` is declared here for the same reason it is declared in the harness the
// helpers are lifted from: the adapter's emitted call reaches it when the
// low-level call did not succeed, and an undeclared call is a compile error
// that reads as a broken fixture rather than as an action the contract declined.
interface Vm { function deal(address who, uint256 amount) external; function skip(bool skipTest) external; }
contract Reentrant {
    EtherStore immutable store;
    bool entered;
    constructor() { store = new EtherStore(); }
    function attack() external {
        store.deposit{value: 3 ether}();
        store.withdraw(1 ether);
    }
    receive() external payable {
        if (!entered) { entered = true; store.withdraw(1 ether); }
    }
}
contract Gate {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256(\"hevm cheat code\")))));
    // `_skipUnavailable`, lifted from the harness with the rest of the helpers,
    // reaches the cheat code through `_vm`.  The gate holds the handle as a
    // constant and the harness template reads the address instead, so both
    // define this and the helper itself needs only one spelling.
    function _vm() private returns (Vm) { return vm; }
    function testInvariant_reentrancy() public {
%s
    }
}
""" % (import_name, body)
    return "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + test_source, body


def _test_source(contract: str, import_name: str, tests: list[tuple[str, str]]) -> tuple[str, str]:
    functions = []
    bodies = []
    for index, (template, rendered) in enumerate(tests):
        indented = rendered.replace(chr(10), chr(10) + "        ")
        functions.append(f"    function testInvariant_{index}() public {{\n        address target = address(new {contract}());\n        {indented}\n    }}")
        bodies.append(rendered)
    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import \"../src/%s\";
// `skip` is declared here for the same reason it is declared in the harness the
// helpers are lifted from: the adapter's emitted call reaches it when the
// low-level call did not succeed, and an undeclared call is a compile error
// that reads as a broken fixture rather than as an action the contract declined.
interface Vm { function deal(address who, uint256 amount) external; function skip(bool skipTest) external; }
contract Gate {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256(\"hevm cheat code\")))));
    function _vm() private returns (Vm) { return vm; }
%s
%s
}
""" % (import_name, _harness_helpers(), "\n".join(functions))
    return source, "\n\n".join(bodies)


def _run(root: Path, forge: Path) -> tuple[int, str]:
    completed = subprocess.run([str(forge), "test", "--root", str(root), "--offline", "--match-contract", "Gate", "-vv"],
                               cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    return completed.returncode, output


def _variant(fixture_dir: Path, variant: str, tests: list[tuple[str, str]], poc: bool,
             temp_root: Path, forge: Path) -> dict:
    source_path = _source_file(fixture_dir / variant)
    source = source_path.read_text(encoding="utf-8")
    root = temp_root / variant
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir()
    shutil.copyfile(source_path, root / "src" / source_path.name)
    if poc:
        test_source, body = _poc_source(source_path.name)
    else:
        test_source, body = _test_source(_contract_name(source), source_path.name, tests)
    (root / "test" / "Gate.t.sol").write_text(test_source, encoding="utf-8")
    # The optimizer plus the IR pipeline is what lets a gate that holds several
    # ledger reads at once compile at all: without it the legacy 16-slot stack
    # limit is exceeded and solc fails with an internal "stack too deep" error
    # that says nothing about the fixture.  `via_ir` exists from 0.8.13 on and is
    # simply ignored by profiles that predate it.
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\ncache_path = "cache"\n'
        'libs = []\nauto_detect_solc = true\noffline = true\n'
        'optimizer = true\noptimizer_runs = 200\nvia_ir = true\n', encoding="utf-8")
    code, output = _run(root, forge)
    lowered = output.lower()
    compile_error = any(marker in lowered for marker in ("compilation failed", "compiler run failed", "error["))
    return {"variant": variant, "returnCode": code, "passed": code == 0,
            "compileError": compile_error, "sourceSha256": hashlib.sha256(source.encode()).hexdigest(),
            "assertionSha256": hashlib.sha256(body.encode()).hexdigest(),
            "outputTail": output[-2000:]}


def verify(*, fixture_root: Path = FIXTURE_ROOT, forge: Path | None = None,
           output: Path | None = None) -> dict:
    forge = Path(forge or os.environ.get("FORGE", ROOT / "work" / "tools" / "forge")).resolve()
    if not forge.is_file() or not os.access(forge, os.X_OK):
        raise RuntimeError(f"forge executable unavailable: {forge}")
    rows = []
    fixture_dirs = sorted(path for path in fixture_root.iterdir() if path.is_dir())
    if not fixture_dirs:
        raise RuntimeError(f"no fixture directories found: {fixture_root}")
    with tempfile.TemporaryDirectory(prefix="reverse-fixtures-") as temp:
        temp_root = Path(temp)
        for fixture_dir in fixture_dirs:
            meta_path = fixture_dir / "meta.json"
            if not meta_path.is_file():
                raise RuntimeError(f"missing metadata: {meta_path}")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            templates = [item.strip() for item in str(meta.get("template", "")).split(",") if item.strip()]
            if not templates:
                raise RuntimeError(f"missing templates: {meta_path}")
            for variant in ("correct", "violating"):
                _source_file(fixture_dir / variant)
            poc = meta.get("role") == "poc"
            tests = []
            if not poc:
                params = meta.get("params")
                if not isinstance(params, dict):
                    raise RuntimeError(f"missing params for executable fixture: {meta_path}")
                for template in templates:
                    setup, body = _render_assertion(fixture_dir.name, template, params)
                    tests.append((template, (setup + "\n" if setup else "") + body))
            correct = _variant(fixture_dir, "correct", tests, poc, temp_root / fixture_dir.name, forge)
            violating = _variant(fixture_dir, "violating", tests, poc, temp_root / fixture_dir.name, forge)
            if correct["assertionSha256"] != violating["assertionSha256"]:
                raise RuntimeError(f"assertion source differs between variants: {fixture_dir.name}")
            if correct["compileError"] or not correct["passed"]:
                raise RuntimeError(f"correct fixture did not pass: {fixture_dir.name}\n{correct['outputTail']}")
            if violating["compileError"] or violating["passed"]:
                raise RuntimeError(f"violating fixture did not fail assertion: {fixture_dir.name}\n{violating['outputTail']}")
            rows.append({"fixture": fixture_dir.name, "correct": correct, "violating": violating,
                         "templates": templates, "poc": poc})
    result = {"schemaVersion": 1, "state": "passed", "fixtureCount": len(rows), "fixtures": rows,
              "forge": str(forge), "assertionsIdentical": True}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(f".{output.name}.tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(output)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=FIXTURE_ROOT)
    parser.add_argument("--forge", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(fixture_root=args.fixtures, forge=args.forge, output=args.output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"schemaVersion": 1, "state": "failed", "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps({"state": result["state"], "fixtureCount": result["fixtureCount"],
                      "output": str(args.output) if args.output else None}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
