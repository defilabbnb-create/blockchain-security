#!/usr/bin/env python3
"""Produce the ir-reconcile and invariants evidence layers for the benchmark.

The two deep layers had producers for their readers but no producer at all: the
whole benchmark suite scored 0/33 on both because nothing ever wrote
``ir-reconcile.json`` or ``invariants.json``.  This script closes that gap using
the engine that already exists in this repository instead of a new scanner:

    verified source + cached soljson
        -> Slither call graph -> unified IR              (unified_ir.from_call_graph)
        -> compiled runtime bytecode -> bytecode IR       (bytecode_analysis)
        -> reconciliation                                (ir_reconcile.reconcile)
        -> role-aware invariants                         (invariant_gen.generate_invariants)
        -> generated assertions -> forge, offline         (harness_gen/dynamic_runner)

Every stage is bound to the source bytes the evidence claims to describe.  A
mismatch yields ``failed`` evidence rather than a plausible-looking result, and a
role or renderer that genuinely cannot be resolved is recorded as
``unavailable`` rather than being filled in with a guessed category.

The script only reads the benchmark sources.  It never edits a ``.sol`` file or
a ``ground-truth.json``, never relaxes an assertion, and never reaches the
network: only soljson releases already cached under ``work/compiler-cache`` are
usable, and execution is pinned to an isolated offline boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
CONTRACTS = ROOT / "benchmark" / "contracts"
COMPILER_CACHE = ROOT / "work" / "compiler-cache"
FORGE = ROOT / "work" / "tools" / "forge"
SOLC_BRIDGE = SCRIPTS / "campaign-solc.cjs"
CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")

# Environment variables that would let a harness reach a remote chain.  The deep
# layers are an offline experiment, so they are removed from every child process
# rather than trusted to be overridden downstream.
OFFLINE_STRIPPED_ENV = (
    "RPC_URL",
    "DYNAMIC_FORK_RPC_URL",
    "DYNAMIC_FORK_BLOCK_NUMBER",
    "ETH_RPC_URL",
    "FOUNDRY_ETH_RPC_URL",
    "ALCHEMY_API_KEY",
    "INFURA_API_KEY",
)
LOCAL_CHAIN_ID = 31337


def _module(filename: str, name: str):
    """Load one of the repository's hyphenated scripts as a module."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module_unavailable:{filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8"))


def _atomic_json(path: Path, payload: Any) -> None:
    """Write evidence atomically so a killed run never leaves half a document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _major(version: str) -> int:
    """Return the language generation of a dotted compiler version.

    The generated wrappers have to differ across the 0.4/0.5 language boundary:
    a contract instance converts to `address` implicitly in 0.4 and only with an
    explicit cast from 0.5 on, so the same source compiles on one side and not
    the other.  Solidity numbers these `0.4.x` and `0.8.x`, so comparing the
    leading number would treat every 0.x release as pre-0.5; the minor number is
    what carries the distinction.  An unparsable version is treated as modern,
    which is the side that fails loudly rather than silently compiling to
    something else.
    """
    match = re.match(r"\s*0\.(\d+)\.", str(version or ""))
    if not match:
        return 99 if str(version or "").strip() else 0
    minor = int(match.group(1))
    # 0.4 is the last generation with the implicit contract-to-address cast.
    return 4 if minor <= 4 else 5


def offline_environment() -> dict[str, str]:
    """Return a child environment pinned to the isolated local boundary."""
    environment = dict(os.environ)
    for key in OFFLINE_STRIPPED_ENV:
        environment.pop(key, None)
    environment["FOUNDRY_OFFLINE"] = "true"
    environment.pop("SOLC_VERSION", None)
    return environment


def _binding_error(case_id: str, source_sha256: str, compiler_version: str,
                   compiler_sha256: str, payload: dict[str, Any]) -> str | None:
    """Reuse the poc runner's binding contract for the deep layers.

    Evidence that does not describe exactly this source, compiled by exactly this
    cached compiler, inside exactly this execution boundary is not evidence about
    this case.  Reusing ``benchmark-dynamic._binding_error`` keeps one definition
    of "bound" instead of two that can drift apart.
    """
    reference = _module("benchmark-dynamic.py", "benchmark_dynamic_binding")
    return reference._binding_error(payload, case_id, source_sha256,
                                    compiler_version, compiler_sha256)


def _local_execution_boundary() -> dict[str, Any]:
    """Describe the offline boundary every deep-layer result was produced in.

    These are the literal fields ``benchmark-dynamic._binding_error`` validates,
    so the deep layers declare the same boundary the poc runner does rather than
    an approximate one: no fork, no RPC, no signing, no external transaction and
    no network write outside the local process.
    """
    return {"mode": "isolated_in_process", "requestedMode": "isolated_in_process",
            "chainId": LOCAL_CHAIN_ID, "forkState": "not_performed", "requestedFork": False,
            "externalTransactions": False, "externalSigning": False,
            "networkWrites": "local_only", "rpcEndpoint": {"state": "not_configured"},
            "scope": "locally compiled verified source; dynamic behaviour observed "
                     "only inside the generated offline assertion harness"}


def _case_ids() -> list[str]:
    if not CONTRACTS.is_dir():
        return []
    return sorted(entry.name for entry in CONTRACTS.iterdir()
                  if entry.is_dir() and CASE_ID_PATTERN.fullmatch(entry.name)
                  and (entry / "ground-truth.json").is_file())


def _read_case(case_id: str) -> dict[str, Any]:
    case_dir = CONTRACTS / case_id
    ground_truth = json.loads((case_dir / "ground-truth.json").read_text(encoding="utf-8"))
    source_name = ground_truth.get("sourceFile")
    if not isinstance(source_name, str) or not source_name or Path(source_name).name != source_name:
        raise ValueError("benchmark sourceFile must be a safe file name")
    source_bytes = (case_dir / source_name).read_bytes()
    return {"caseId": case_id, "caseDir": case_dir, "groundTruth": ground_truth,
            "sourceName": source_name, "sourceBytes": source_bytes,
            "sourceText": source_bytes.decode("utf-8"),
            "sourceSha256": _sha256_bytes(source_bytes)}


def _compiler_for(case: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Resolve the cached soljson release declared by the ground truth.

    ``review-static.compiler`` only ever looks inside ``work/compiler-cache``; it
    never downloads.  A missing release therefore raises instead of reaching the
    network, which is the intended failure mode here.
    """
    version = case["groundTruth"].get("solcVersion")
    if not isinstance(version, str) or not version:
        raise ValueError("ground truth does not declare a solcVersion")
    static = _module("review-static.py", "review_static_compiler")
    soljson, metadata = static.compiler(version)
    return Path(soljson), metadata


def _compile_standard_json(case: dict[str, Any], soljson: Path, solc_version: str) -> dict[str, Any]:
    """Compile the single verified source unit with the cached compiler.

    Imports are not resolved here on purpose: a benchmark sample that needs
    remote imports has no locally verifiable compilation, and reporting that is
    more useful than inventing a dependency tree.
    """
    request = {
        "language": "Solidity",
        "sources": {case["sourceName"]: {"content": case["sourceText"]}},
        "settings": {
            "outputSelection": {"*": {"*": ["evm.bytecode.object", "evm.bytecode.linkReferences",
                                            "evm.deployedBytecode.object",
                                            "abi"]}},
        },
    }
    environment = offline_environment()
    environment["CAMPAIGN_SOLJSON"] = str(soljson)
    try:
        completed = subprocess.run(["node", str(SOLC_BRIDGE), "--standard-json"],
                                   input=json.dumps(request), cwd=ROOT, env=environment,
                                   capture_output=True, text=True, timeout=180, check=False)
    except (subprocess.TimeoutExpired, OSError) as error:
        raise RuntimeError(f"compiler_bridge_failed:{type(error).__name__}") from error
    if completed.returncode != 0:
        raise RuntimeError("compiler_bridge_failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("compiler_bridge_output_invalid") from error
    if payload.get("errors"):
        for error in payload["errors"]:
            if isinstance(error, dict) and error.get("severity") == "error":
                raise RuntimeError("solidity_compilation_error")
    contracts = (payload.get("contracts") or {}).get(case["sourceName"]) or {}
    stem = Path(case["sourceName"]).stem
    # Contracts that actually produced runtime bytecode, with the bytecode size
    # as a tiebreaker signal: a real contract has code, an abstract one does not.
    named = sorted(
        (name for name, entry in contracts.items()
         if isinstance((entry.get("evm") or {}).get("deployedBytecode"), dict)
         and isinstance((entry["evm"]["deployedBytecode"]).get("object"), str)
         and len(entry["evm"]["deployedBytecode"]["object"]) > 2),
        key=lambda name: (len(contracts[name]["evm"]["deployedBytecode"]["object"]), name),
        reverse=True,
    )
    # The contract whose `contract` declaration matches the source stem wins.
    if stem in named:
        return {"contractName": stem, "artifact": contracts[stem],
                "compiledContracts": sorted(contracts)}
    # Otherwise the target has to come from the source text rather than from the
    # file name: samples such as `02-incorrect_constructor_name1` declare
    # `contract Missing`, and no spelling of the file name can recover that.
    # Picking alphabetically instead compiled and analysed an unrelated contract,
    # so the call graph had no entrypoint and the IR came back function-less --
    # the sample then scored as a detection miss for a reason that had nothing to
    # do with detection.
    declared = _declared_contract_names(case["sourceText"])
    for candidate in declared:
        if candidate in named:
            return {"contractName": candidate, "artifact": contracts[candidate],
                    "compiledContracts": sorted(contracts)}
    if named:
        # Largest bytecode wins over alphabetical order: an abstract or library
        # contract compiles to something far smaller than the real target.
        return {"contractName": named[0], "artifact": contracts[named[0]],
                "compiledContracts": sorted(contracts)}
    raise RuntimeError("compiled_runtime_bytecode_absent")


def _declared_contract_names(source_text: str) -> list[str]:
    """Return the contract names declared in the source, in declaration order.

    Comments and string literals are stripped first so a contract name quoted in
    prose cannot be mistaken for a declaration.
    """
    import re as _re
    try:
        module = _module("source_vuln_evidence.py", "source_vuln_evidence_targets")
        code = module.strip_comments_and_strings(source_text)
    except Exception:
        code = source_text
    return [match.group(1) for match in
            _re.finditer(r'\bcontract\s+([A-Za-z_$][A-Za-z0-9_$]*)', code)]


def _source_ir(case: dict[str, Any], soljson: Path, compiler_version: str,
               contract_name: str) -> dict[str, Any]:
    """Build the source-side unified IR through the existing static chain.

    ``review-static.analyze`` already compiles, walks the call graph and writes
    ``unified-ir.json``.  Driving it here keeps the deep layers on exactly the
    IR that the static layer reasoned about, rather than a parallel build that
    could disagree with the evidence already in the suite.

    ``contract_name`` is mandatory: the call graph resolves entrypoints from
    ``compilationTarget``, so an empty target silently yields a function-less IR
    and every downstream role would be undetectable for the wrong reason.
    """
    if not contract_name:
        raise ValueError("compilation target contract is required")
    work_dir = case["caseDir"] / "deep-layers-work"
    work_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = work_dir / "source-bundle.json"
    settings = {"compilationTarget": {case["sourceName"]: contract_name}}
    _atomic_json(bundle_path, {
        "sources": {case["sourceName"]: {"content": case["sourceText"]}},
        "compilation": {"compilerVersion": compiler_version,
                        # The cache key in review-static.analyze hashes sources, the
                        # compiler version and these settings.  compilationTarget
                        # therefore has to live here: kept only under metadata it is
                        # outside the key, so a run that targets a different contract
                        # would silently replay the previous run's entrypoint-less IR.
                        "compilerSettings": settings},
        "stdJsonInput": {"language": "Solidity",
                         "sources": {case["sourceName"]: {"content": case["sourceText"]}},
                         "settings": settings},
        "metadata": {"settings": settings},
    })
    static = _module("review-static.py", "review_static_analysis")
    environment = offline_environment()
    environment["CAMPAIGN_SOLJSON"] = str(soljson)
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(environment)
        result = static.analyze(bundle_path)
    finally:
        os.environ.clear()
        os.environ.update(previous)
    if result.get("state") not in {"completed", "partial"}:
        raise RuntimeError("static_analysis_incomplete")
    ir_path = work_dir / "unified-ir.json"
    if not ir_path.is_file():
        raise RuntimeError("unified_ir_not_produced")
    return json.loads(ir_path.read_text(encoding="utf-8"))


def _bytecode_ir(case: dict[str, Any], compiled: dict[str, Any]) -> dict[str, Any]:
    """Build the bytecode-side IR from the locally compiled runtime code."""
    analysis = _module("bytecode_analysis.py", "bytecode_analysis_deep")
    deployed = (compiled["artifact"].get("evm") or {}).get("deployedBytecode") or {}
    runtime = deployed.get("object")
    if not isinstance(runtime, str):
        raise RuntimeError("compiled_runtime_bytecode_absent")
    # soljson emits bare hex while every bytecode entry point in this repository
    # requires the 0x-prefixed form; normalize here rather than at each call site.
    hex_body = runtime[2:] if runtime.startswith("0x") else runtime
    if not hex_body or len(hex_body) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", hex_body):
        raise RuntimeError("compiled_runtime_bytecode_malformed")
    report = analysis.analyze_runtime_bytecode(f"0x{hex_body.lower()}", chain_id=LOCAL_CHAIN_ID)
    unified = _module("unified_ir.py", "unified_ir_bytecode")
    return unified.from_bytecode_report(report)


def _ir_reconcile_evidence(case: dict[str, Any], compiler_metadata: dict[str, Any],
                           solc_version: str) -> dict[str, Any]:
    """Reconcile source IR against bytecode IR and emit the eval-shaped document."""
    base = {
        "schemaVersion": 1,
        "caseId": case["caseId"],
        # eval_pipeline._read_layer_file binds on this exact key, so it is the raw
        # source digest rather than the canonical bundle digest the IR uses.
        "sourceSha256": case["sourceSha256"],
        "sourceBundleSha256": _canonical_sha256({case["sourceName"]: case["sourceText"]}),
        "compilerVersion": solc_version,
        "compilerSha256": compiler_metadata.get("sha256"),
        "executionBoundary": _local_execution_boundary(),
        "generatedAt": _module("corpus_shards.py", "corpus_shards_clock").now(),
        "detectedIssues": [],
    }
    try:
        soljson, compiler_metadata = _compiler_for(case)
        compiled = _compile_standard_json(case, soljson, solc_version)
        source_ir = _source_ir(case, soljson, solc_version, compiled["contractName"])
        bytecode_ir = _bytecode_ir(case, compiled)
    except Exception as error:  # recorded, never silently dropped
        base["state"] = "unavailable"
        base["reason"] = f"ir_reconcile_inputs_unavailable:{str(error)[:160]}"
        return base
    reconciliation = _module("ir_reconcile.py", "ir_reconcile_deep").reconcile(source_ir, bytecode_ir)
    unresolved = reconciliation.get("unresolved")
    # Partial IR evidence still reconciles what it can: the unresolved detail names
    # which comparison axes were unavailable, while the recorded comparisons stay
    # valid.  Scoring the layer as available-with-measurements is more useful and
    # more honest than discarding a completed comparison, and the unresolved axes
    # are carried through verbatim so the limitation cannot be lost.
    base["state"] = "completed"
    if unresolved:
        base["partialReconciliation"] = unresolved
    base["reconciliation"] = reconciliation
    base["sourceIrSha256"] = _canonical_sha256(source_ir)
    base["bytecodeIrSha256"] = _canonical_sha256(bytecode_ir)
    base["sourceFaithfulnessScore"] = reconciliation.get("sourceFaithfulnessScore")
    base["bytecodeOnlyFunctions"] = reconciliation.get("bytecodeOnlyFunctions", [])
    base["sourceOnlyFunctions"] = reconciliation.get("sourceOnlyFunctions", [])
    base["divergentControlFlow"] = reconciliation.get("divergentControlFlow", [])
    base["hiddenEntrypointCount"] = len(base["bytecodeOnlyFunctions"])
    # The reconcile layer reports IR agreement, not vulnerability classes.  The
    # repository has no mapping from a hidden selector to a ground-truth category,
    # and eval_pipeline.score_case compares against knownIssues by exact string,
    # so any label invented here would be counted as a false positive.  The layer
    # therefore contributes an explicit, measured empty observation set and keeps
    # every divergence in the structured fields instead.
    base["detectedIssues"] = []
    base["observationBasis"] = ("none:no_ground_truth_category_mapping_for_ir_divergence")
    base["divergenceCount"] = (len(base["bytecodeOnlyFunctions"]) + len(base["sourceOnlyFunctions"])
                               + len(base["divergentControlFlow"]))
    base["confirmedVulnerability"] = False
    base["interpretation"] = ("IR agreement between locally compiled source and its own runtime "
                              "bytecode; a divergence is a review lead, not a confirmed defect")
    return base


def _local_deployment(case: dict[str, Any], harness_dir: Path, compiled: dict[str, Any]) -> dict[str, Any]:
    """Add a self-deploying target test to the harness and return its address.

    The generated assertions read the target through the ``INVARIANT_TARGET``
    environment variable and declare their own minimal ``Vm`` interface, so no
    forge-std checkout is needed.  ``harness_gen`` deliberately reports
    ``adapter_required`` for every target because constructor arguments cannot be
    inferred, which is the right default for production use; for a benchmark
    sample the source file is itself the ground truth, so a no-argument
    constructor is deployed verbatim.  A sample that needs constructor arguments
    stays unavailable rather than being deployed with invented values.

    Every ``forge test`` run starts a fresh EVM, so a contract deployed by a
    separate earlier invocation has no code at that address when the assertions
    run.  Deployment therefore happens as a test inside the same suite that
    executes the assertions, and the address is published by writing it to a file
    the assertions read at execution time.
    """
    abi = compiled["artifact"].get("abi") or []
    constructor = next((item for item in abi if item.get("type") == "constructor"), None)
    inputs = (constructor or {}).get("inputs") if isinstance(constructor, dict) else None
    if inputs:
        return {"state": "adapter_required", "reason": "constructor_arguments_missing",
                "missing": [item.get("name") or f"arg{index}" for index, item in enumerate(inputs)]}
    contract_name = compiled["contractName"]
    source_name = case["sourceName"]
    # The wrapper has to be compilable by the same compiler as its target, so its
    # pragma is copied from the target rather than chosen independently.  A fixed
    # `>=0.8.19` excluded every pre-0.8 sample outright; a fixed `>=0.4.22`
    # would do the same to the 0.4.10-0.4.21 half.  Only a literal pinned pragma
    # is honoured -- a range would let the two units drift apart again -- and the
    # fallback floor matches the oldest compiler this corpus pins.
    pinned = re.search(r'pragma\s+solidity\s+(?:solidity\s+)?'
                       r'([0-9]+\.[0-9]+\.[0-9]+)\s*;', case["sourceText"])
    # The ground truth names the exact compiler the sample is graded against, and
    # that -- not the pragma, which is usually a range -- is what the wrapper has
    # to satisfy.  Reading the version from the pragma defaulted the 0.4.19
    # samples to the 0.8 branch and emitted `uint`, which does not parse before
    # 0.4.22.
    compiler_version = str(case["groundTruth"].get("solcVersion") or "")
    version_tuple = compiler_version if re.match(r'\d+\.\d+\.\d+', compiler_version) else (
        pinned.group(1) if pinned else "0.8.19")
    wrapper_pragma = pinned.group(1) if pinned else f'>={version_tuple}'
    # `uint` as an alias for `uint256` only arrived in 0.4.22, so a target older
    # than that needs the explicit width for the wrapper's locals to parse.
    wide = "uint256" if tuple(int(part) for part in version_tuple.split(".")) < (0, 4, 22) else "uint"
    # The generated assertion reads the target from the INVARIANT_TARGET
    # environment variable, but every ``forge test`` run starts a fresh EVM, so an
    # address captured from an earlier invocation has no code by the time the
    # assertions execute.  The assertion therefore deploys the target itself when
    # the environment variable is absent, and the recorded address is only used
    # for provenance.  vm.writeFile is unavailable without forge-std, so the
    # deployment is done inline in Solidity instead of through a Python step.
    # The wrapper's pragma has to be compatible with the target's own pragma.
    # Hardcoding `>=0.8.19` here made every pre-0.8 sample unbuildable: forge
    # compiles the whole project at one version, so a 0.4.x target plus a 0.8.x
    # test file is an unsatisfiable constraint and the deployment step returned
    # no address at all.  `address.code` is likewise 0.8-only, so the code check
    # is written with `extcodesize`, which has existed since the Byzantium fork.
    # The contract-to-address cast went the other way and broke the 0.8 samples:
    # assigning a contract instance straight to an `address` local is legal in
    # 0.4 but a type error from 0.5 on, so the explicit cast is emitted only for
    # the modern compilers.
    #
    # The generated file deliberately carries no explanatory comments.  A 0.4.19
    # lexer rejects a `//` comment whose text contains a backtick, which is how
    # the surrounding notes are normally written, and the failure then looks like
    # a syntax error in whatever line follows.  The code-size local is named
    # `deployedSize` rather than `size` for a related reason: several 0.4.x
    # releases reserve `size`, and shadowing it with an assembly slot does not
    # parse.
    cast = "address(deployed)" if _major(
        case["groundTruth"].get("solcVersion")) >= 5 else "deployed"
    # `require` gained a revert-reason argument in 0.4.22, so the pre-0.4.22 half
    # of the corpus only accepts the bare form.  Emitting the two-argument call
    # there is a type error, which the run reported as a failed deployment rather
    # than as the version mismatch it is.
    require_reason = (tuple(int(part) for part in version_tuple.split(".")) >= (0, 4, 22))
    require_form = ('require(deployedSize > 0, "deployment produced no code");'
                    if require_reason else "require(deployedSize > 0);")
    # The `emit` keyword arrived in 0.4.21; earlier releases call the event as a
    # plain function.  Emitting it unconditionally makes every sample pinned
    # below 0.4.21 fail with a ParserError that points at the event's arguments
    # and says nothing about the contract under test.
    emit_call = "emit TargetDeployed" if tuple(
        int(part) for part in version_tuple.split(".")) >= (0, 4, 21) else "TargetDeployed"
    # The 0.4.x compilers cannot instantiate a contract type that comes from
    # another source unit: `new Name()` parses only when the type is declared in
    # the file being compiled, so an importing wrapper fails with a ParserError
    # pointing at the `(` of the `new` expression.  Eight corpus samples pinned
    # between 0.4.10 and 0.4.25 never reached their assertions because of it, and
    # the layer reported a deployment failure that described the compiler rather
    # than the contract.  Declaring the target inside the wrapper makes the type
    # local; the target text is spliced in verbatim, only its location changes.
    pre_0_5 = tuple(int(part) for part in version_tuple.split(".")) < (0, 5, 0)
    if pre_0_5:
        target_text = re.sub(r'^\s*pragma\s+solidity[^;]*;\s*', '',
                             case["sourceText"].strip(), count=1, flags=re.M)
        # The wrapper already declares an SPDX identifier; a target that ships
        # one as well makes solc 0.8 reject the unit outright.
        target_text = re.sub(r'^\s*//\s*SPDX-License-Identifier:.*$', '',
                             target_text, count=1, flags=re.M).strip()
        declaration = f'\n{target_text}\n'
        opening = f'''
contract DeepTarget {{'''
    else:
        declaration = ""
        opening = f'''
import "../src/{source_name}";

contract DeepTarget {{'''
    (harness_dir / "test" / "DeepTarget.t.sol").write_text(f'''// SPDX-License-Identifier: MIT
pragma solidity {wrapper_pragma};
{declaration}{opening}
    event TargetDeployed(address target);

    function testDeployTarget() public {{
        {contract_name} deployed = new {contract_name}();
        address deployedAddress = {cast};
        {wide} deployedSize;
        assembly {{ deployedSize := extcodesize(deployedAddress) }}
        {require_form}
        {emit_call}(deployedAddress);
    }}
}}
''', encoding="utf-8")
    environment = offline_environment()
    environment.pop("FOUNDRY_OFFLINE", None)
    # -vvvv is required for the emitted event to appear in the trace; at lower
    # verbosity forge reports only that the test passed.
    completed = _forge_with_solc(
        ["test", "--root", str(harness_dir), "--match-test", "testDeployTarget",
         "--match-contract", "DeepTarget", "-vvvv"],
        cwd=harness_dir, environment=environment, version=version_tuple)
    if completed is None:
        return {"state": "failed", "reason": "local_deployment_process_failed", "width": wide}
    output = f"{completed.stdout}\n{completed.stderr}"
    # solc-js 0.4.x cannot instantiate a contract type that was imported from
    # another source unit: `new Name()` parses only when the type is declared in
    # the file being compiled, and the deployment wrapper always imports its
    # target.  The failure is a ParserError pointing at the `(` of the `new`
    # expression, which describes the compiler's limitation rather than the
    # contract under test, so it gets its own reason instead of being folded
    # into a generic deployment failure.
    if "ParserError" in output and "Compiler run failed" in output:
        return {"state": "failed",
                "reason": "solc_0_4_cannot_instantiate_imported_contract_type",
                "compilerVersion": version_tuple, "width": wide,
                "reasonArgument": require_reason}
    # forge links the standard library's timestamp for the 0.4.x compilers by
    # binding `now`; when a target declares its own `now` -- or the linker cannot
    # resolve the symbol -- forge disables dynamic test linking for that file,
    # strips the test function, and then reports "No tests found in project".
    # The contract compiled cleanly, so this is a toolchain limitation rather
    # than an undeployable contract, and it gets its own reason so the sample is
    # not read as a broken target.
    if "No tests found in project" in output:
        unresolved = re.search(r"unresolved symbol `([^`]+)`", output)
        return {"state": "failed",
                "reason": "forge_cannot_link_test_entrypoint_for_target",
                "unresolvedSymbol": unresolved.group(1) if unresolved else None,
                "compilerVersion": version_tuple, "width": wide,
                "reasonArgument": require_reason}
    # forge cannot read the build artifact that soljson 0.4.10 emits: the modern
    # schema requires a `totalCost` field that release never wrote, so forge aborts
    # with "missing field `totalCost`" before any test runs.  This is a toolchain
    # incompatibility rather than anything about the contract under test, and it is
    # named separately so the sample is not read as an undeployable contract.
    if "totalCost" in output or "missing field" in output:
        return {"state": "failed",
                "reason": "forge_cannot_read_legacy_solc_build_artifact",
                "compilerVersion": version_tuple, "width": wide,
                "reasonArgument": require_reason}
    # forge prints the emitted event as "emit TargetDeployed(target: Name: [0x...])".
    match = re.search(r"TargetDeployed\([^)]*?\[?(0x[0-9a-fA-F]{40})\]?\)", output)
    if not match:
        return {"state": "failed", "reason": "local_deployment_produced_no_address",
                "width": wide, "compilerVersion": version_tuple,
                "reasonArgument": require_reason}
    return {"state": "deployed", "contract": contract_name, "sourceUnit": source_name,
            "target": match.group(1), "deployedBy": "harness_local_test_no_forge_std",
            # The assertion wrapper is generated with the same integer width and
            # the same compiler this deployment probe used, so both parse.
            "width": wide, "compilerVersion": version_tuple,
            # Whether `require` takes a revert reason here, carried so the
            # assertion wrapper is generated in the same dialect.
            "reasonArgument": require_reason}


def _forge_with_solc(forge_args: list[str], *, cwd: Path, environment: dict[str, str],
                     timeout: int = 240,
                     version: str | None = None) -> subprocess.CompletedProcess | None:
    """Run Foundry through the checksum-verified solc bridge.

    `forge` cannot compile a pre-0.8 sample on its own here: it resolves the
    compiler through `auto_detect_solc`, finds nothing installed for `^0.4.10`,
    and exits before the test ever runs -- so the deployment step reported "no
    address" for a reason that had nothing to do with the contract.  The bridge
    pins one already-cached soljson release and passes it via `--use`, which is
    the only path in this repository that compiles an old pragma offline.

    The version is passed explicitly whenever the caller knows it.  `auto` picks
    the newest cached release the pragma allows, which for `^0.4.19` is 0.4.26 --
    and 0.4.26 rejects the `function() payable` fallback syntax those samples are
    written in.  A sample graded against 0.4.19 has to be compiled by 0.4.19.

    Returns ``None`` when neither the bridge nor a bare forge run can execute, so
    the caller records unavailability instead of inventing a deployment.
    """
    pinned = version or "auto"
    for command in (
            [sys.executable, str(ROOT / "scripts" / "forge-with-solc.py"),
             "--compiler-version", pinned, "--forge", str(FORGE), *forge_args],
            [str(FORGE), *forge_args]):
        try:
            return subprocess.run(command, cwd=cwd, env=environment,
                                  capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def _refine_assertion_states(harness_dir: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Split a failing forge run into per-assertion results.

    ``dynamic_runner.run_harness`` sees one process exit code and therefore reports
    every assertion in the suite with the same state.  That is correct for its
    aggregate view but it would claim a protocol property was violated when the
    suite actually failed to set up or a getter was missing, so the verdict is
    taken from each assertion's own forge result line.  The shared runner is left
    unchanged and this refinement only narrows what it reported.
    """
    if not any(row.get("state") in {"violated", "passed"} for row in rows):
        return rows
    environment = offline_environment()
    environment.pop("FOUNDRY_OFFLINE", None)
    completed = _forge_with_solc(
        ["test", "--root", str(harness_dir), "--match-test", "testInvariant"],
        cwd=harness_dir, environment=environment)
    if completed is None:
        return rows
    verdicts: dict[str, dict[str, Any]] = {}
    for match in re.finditer(
            r'\[(PASS|FAIL)(?::\s*([^\]]*))?\]\s*testInvariant\(\)', completed.stdout):
        prefix = (match.group(2) or "").strip()
        outcome = {"passed": True, "prefix": prefix}
        if match.group(1) == "FAIL":
            outcome["passed"] = False
            lowered = prefix.lower()
            # A missing getter or a reverted setup means the property was never
            # evaluated; that is unavailability, not an observed violation.
            outcome["setup_failure"] = any(token in lowered for token in
                                            ("unavailable", "no contracts to fuzz",
                                             "invariant testing environment", "has no code",
                                             "produced no code", "deploy"))
        verdicts[_last_hash_prefix(completed.stdout, match.start())] = outcome
    refined = []
    for row in rows:
        identifier = row.get("invariantId") or ""
        verdict = verdicts.get(str(identifier)[:16]) or verdicts.get(str(identifier))
        if verdict is None:
            refined.append(row)
            continue
        if verdict["passed"]:
            row["state"] = "passed"
            row.pop("reason", None)
        elif verdict.get("setup_failure"):
            row["state"] = "unavailable"
            row["reason"] = f"invariant_precondition_unavailable:{_short(verdict.get('prefix'))}"
        else:
            row["state"] = "violated"
            row["reason"] = f"invariant_assertion_failed:{_short(verdict.get('prefix'))}"
        refined.append(row)
    return refined


def _last_hash_prefix(output: str, position: int) -> str:
    """Return the 16-hex test-suite identifier printed before a result line."""
    window = output[:position]
    matches = re.findall(r'test/Invariant_([0-9a-f]{16})\.t\.sol', window)
    return matches[-1] if matches else ""


def _short(value: Any, limit: int = 120) -> str:
    text = str(value or "").strip().replace("\n", " ")
    return text[:limit]


def _inline_target_deployment(harness_dir: Path, source_name: str, contract_name: str,
                              modern: bool = True, wide: str = "uint",
                              reason: bool = True) -> None:
    """Make each generated assertion deploy the target inside its own EVM run.

    ``harness_gen`` renders ``target = vm.envAddress("INVARIANT_TARGET")`` inside
    a ``view`` function.  An address captured from an earlier ``forge test``
    invocation refers to code that no longer exists, because every run starts a
    fresh EVM, and a ``view`` function cannot deploy.  The test is therefore
    rewritten to a non-view function that constructs the target first.  Every
    rendered invariant body and every assertion string is left untouched: only
    how the target is obtained changes.
    """
    pattern = re.compile(
        r'function testInvariant\(\) public \{\s*\n'
        r'\s*address target = Vm\(_cheatCodeAddress\(\)\)\.envAddress\(bytes32\("INVARIANT_TARGET"\)\);\s*\n'
        # Both spellings of the guard: the reason string only exists from 0.4.22
        # on, so the older half of the corpus renders the one-argument form.
        r'\s*require\(_codeSizeAt\(target\) > 0(?:, "INVARIANT_TARGET has no code")?\);'
        # The assertion body moved into its own frame, so the entry forwards to
        # it rather than inlining the body.
        r'(?:\s*\n\s*_assertProtocol\(target\);)?')
    # The rendered bodies address the target as `target` and assign it straight to
    # an `address` local.  That is a type error from 0.5 on, where a contract
    # does not implicitly convert -- and re-casting inside the body would mean
    # rewriting renderer output, which this layer must not do.  So the deployed
    # instance keeps its own name and `target` stays the `address` the bodies
    # already expect, which satisfies every renderer on every compiler version.
    replacement = (
        "function testInvariant() public {\n"
        "        CONTRACT deployedTarget = new CONTRACT();\n"
        f"        address target = {'address(deployedTarget)' if modern else 'deployedTarget'};\n"
        f"        {wide} targetSize;\n"
        "        assembly { targetSize := extcodesize(target) }\n"
        # `require` only accepted a revert reason from 0.4.22 on; the older half
        # of the corpus rejects the two-argument form outright.
        + ('        require(targetSize > 0, "target deployment produced no code");'
           if reason else "        require(targetSize > 0);")
        # The frame split is not optional: the body has to run somewhere the
        # legacy 16-slot stack can hold it, and the entry below has to call it.
        + "\n        _assertProtocol(target);")
    for path in sorted((harness_dir / "test").glob("Invariant_*.t.sol")):
        text = path.read_text(encoding="utf-8")
        updated = pattern.sub(replacement.replace("CONTRACT", contract_name), text)
        if updated == text:
            continue
        # forge treats every public function of a test contract as a test target.
        # The generated invariantId()/description getters are not tests, and
        # leaving them public makes forge fail the suite with
        # "failed to set up invariant testing environment: No contracts to fuzz",
        # which would be reported as a violated protocol property.  They become
        # internal so only testInvariant is executed; the values are unchanged.
        updated = re.sub(r'\n    bytes32 public constant invariantId',
                         '\n    bytes32 internal constant invariantId', updated)
        updated = re.sub(r'\n    string public constant description',
                         '\n    string internal constant description', updated)
        # The 0.4.x compilers cannot instantiate a contract type declared in
        # another source unit: `new Name()` parses only when the type is visible in
        # the file being compiled, and a test that `import`s its target fails with
        # a ParserError pointing at the `(` of the `new` expression.  Eight corpus
        # samples pinned between 0.4.10 and 0.4.25 were therefore never deployed at
        # all.  Declaring the contract in the test's own source unit makes the
        # type local, so the same deployment compiles on every release.  The target
        # text is spliced in verbatim -- only where it is declared changes.
        target_source = (harness_dir / "src" / source_name)
        declaration = ""
        if target_source.exists():
            declaration = target_source.read_text(encoding="utf-8").strip()
            # Only the pragma is dropped: the file already declares one, and two
            # pragmas in one unit is a parse error on every release.
            declaration = re.sub(r'^\s*pragma\s+solidity[^;]*;\s*', '', declaration,
                                 count=1, flags=re.M)
            # The generated file carries its own SPDX identifier, and a target
            # that ships one as well makes solc 0.8 reject the unit with
            # "Multiple SPDX license identifiers found in source file".  The
            # 0.4.x compilers ignore the header entirely, which is why this only
            # surfaced once the older samples started deploying.
            declaration = re.sub(r'^\s*//\s*SPDX-License-Identifier:.*$', '',
                                 declaration, count=1, flags=re.M).strip()
        preamble = (declaration + "\n\n") if declaration else (
            f'import {{ {contract_name} }} from "../src/{source_name}";\n')
        updated = re.sub(
            r'pragma solidity ([^;\n]+);\n',
            lambda pragma_match: f'pragma solidity {pragma_match.group(1)};\n\n',
            updated, count=1)
        marker = "contract Invariant_"
        index = updated.index(marker)
        # The declaration goes at file scope, immediately before the test
        # contract.  Splicing it inside the contract's own braces instead parses
        # as a member declaration and every sample then failed with
        # "Function, variable, struct or modifier declaration expected" pointing
        # at the target's `contract` keyword.
        updated = updated[:index] + preamble + updated[index:]
        path.write_text(updated, encoding="utf-8")


def _invariants_evidence(case: dict[str, Any], compiler_metadata: dict[str, Any],
                         solc_version: str) -> dict[str, Any]:
    """Generate role-aware invariants, execute them offline, and emit evidence."""
    clock = _module("corpus_shards.py", "corpus_shards_clock")
    base = {
        "schemaVersion": 1,
        "caseId": case["caseId"],
        "sourceSha256": case["sourceSha256"],
        "sourceBundleSha256": _canonical_sha256({case["sourceName"]: case["sourceText"]}),
        "compilerVersion": solc_version,
        "compilerSha256": compiler_metadata.get("sha256"),
        "executionBoundary": _local_execution_boundary(),
        "generatedAt": clock.now(),
        "detectedIssues": [],
    }
    try:
        soljson, resolved_metadata = _compiler_for(case)
        compiled = _compile_standard_json(case, soljson, solc_version)
        source_ir = _source_ir(case, soljson, solc_version, compiled["contractName"])
    except Exception as error:
        base["state"] = "unavailable"
        base["reason"] = f"invariant_inputs_unavailable:{str(error)[:160]}"
        return base
    invariant_gen = _module("invariant_gen.py", "invariant_gen_deep")
    bundle_sha256 = _canonical_sha256({case["sourceName"]: case["sourceText"]})
    # The compiler's ABI names the getters solc synthesises for `public` state
    # variables -- both the scalar `fee()` and the mapping `balances(address)`.
    # Slither's call graph only walks user-written functions, so without these a
    # contract with a plainly readable `uint256 public fee` looks like it exposes
    # no state and its role assertions are all dropped as adapter-required.
    abi_getters = sorted({("%s(%s)" % (entry["name"], ",".join(
        argument.get("type", "") for argument in entry.get("inputs") or [])))
        for entry in (compiled["artifact"].get("abi") or [])
        if entry.get("type") == "function"
        and isinstance(entry.get("name"), str)
        and entry.get("name")})
    # The verified source text is handed to the generator because the IR does not
    # record whether a low-level call's result was checked, and several samples
    # record no call at all.  The bytes are the same ones hashed into
    # base["sourceSha256"] above, so the observation cannot drift from the source
    # this evidence claims to describe.
    invariants = invariant_gen.generate_invariants(source_ir, source_sha256=bundle_sha256,
                                                    source_text=case["sourceText"],
                                                    abi_getters=abi_getters)
    base["declaredInvariantsState"] = invariants.get("state")
    base["detectedRoles"] = invariants.get("detectedRoles", [])
    base["unresolved"] = invariants.get("unresolved", [])
    base["invariantIds"] = [row.get("invariantId") for row in invariants.get("invariants", [])]
    # The declared invariants have to travel with the evidence.  Without this the
    # written document only carried `invariantIds`, so every consumer -- the
    # coverage report, the web view, any audit -- read a sample as having zero
    # invariants even when generation had produced them.
    base["invariants"] = invariants.get("invariants", [])
    if invariants.get("state") != "available":
        # Role recognition did not succeed.  Recording that is the honest result;
        # fitting a template to force coverage would invent the very evidence this
        # layer exists to measure.
        base["state"] = "unavailable"
        base["reason"] = "invariant_templates_unavailable"
        return base
    stage = case["caseDir"] / "deep-layers-work" / "invariants"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)
    harness_gen = _module("harness_gen.py", "harness_gen_deep")
    source_bundle = {"sources": {case["sourceName"]: {"content": case["sourceText"]}},
                     "metadata": {"settings": {"compilationTarget": {case["sourceName"]: compiled["contractName"]}}},
                     "abi": (compiled["artifact"].get("abi") or [])}
    manifest = harness_gen.generate_harness(invariants, source_bundle, stage / "harness",
                                            compiler_version=solc_version)
    base["harnessSha256"] = _canonical_sha256(manifest)
    base["adapterRequiredCount"] = manifest.get("adapterRequiredCount", 0)
    harness_dir = stage / "harness"
    deployment = _local_deployment(case, harness_dir, compiled)
    base["deploymentState"] = deployment.get("state")
    base["deployment"] = {key: deployment.get(key) for key in
                          ("state", "reason", "contract", "sourceUnit", "missing", "target")
                          if key in deployment}
    runner = _module("dynamic_runner.py", "dynamic_runner_deep")
    target = deployment.get("target")
    if not (deployment.get("state") == "deployed" and isinstance(target, str) and target.startswith("0x")):
        base["state"] = "unavailable"
        base["reason"] = "local_deployment_unavailable"
        base["detectedIssues"] = []
        return base
    # Each forge test run starts a fresh EVM, so an address obtained from a
    # previous invocation has no code when the assertions execute.  The generated
    # assertion therefore deploys the target itself; the environment variable is
    # only provenance for the address observed during the deployment probe.
    _inline_target_deployment(harness_dir, case["sourceName"], compiled["contractName"],
                          modern=_major(case["groundTruth"].get("solcVersion")) >= 5,
                          wide=deployment.get("width") or "uint",
                          reason=deployment.get("reasonArgument") is not False)
    # dynamic_runner short-circuits on the adapter_required deployment that
    # harness_gen always writes.  The contract really is deployed here, so the
    # recorded deployment state is replaced with the measured one; run_harness
    # itself is untouched and still reports every assertion it could not execute.
    # The exact compiler is carried through because `auto` selection would pick a
    # newer release from the same pragma range and reject the older fallback
    # syntax these samples use.
    harness_json = harness_dir / "harness.json"
    on_disk = json.loads(harness_json.read_text(encoding="utf-8"))
    on_disk["deployment"] = {"state": "deployed", "target": target,
                             "compilerVersion": deployment.get("compilerVersion")}
    _atomic_json(harness_json, on_disk)
    environment = offline_environment()
    environment["INVARIANT_TARGET"] = target
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(environment)
        rows = runner.run_harness(harness_dir, mode="local",
                                  forge=ROOT / "scripts" / "forge-with-solc.py"
                                  if (ROOT / "scripts" / "forge-with-solc.py").is_file()
                                  else (FORGE if FORGE.is_file() else None),
                                  timeout_seconds=180)
    finally:
        os.environ.clear()
        os.environ.update(previous)
    rows = _refine_assertion_states(harness_dir, rows)
    base["results"] = rows
    base["executedAssertionCount"] = sum(1 for row in rows
                                          if row.get("state") in {"passed", "violated"})
    states = [row.get("state") for row in rows]
    violated = [row for row in rows if row.get("state") == "violated"]
    if violated:
        # A violated invariant means the assertion observed the property failing in
        # this harness.  That is an experiment result, never a confirmed defect.
        base["state"] = "completed"
        base["outcome"] = "invariant_violated"
        base["violatedTemplates"] = sorted(str(row.get("template") or "unnamed") for row in violated)
        # Templates name protocol properties (share_price_monotonic), while
        # knownIssues name vulnerability classes (erc4626_donation).  Nothing in
        # this repository maps between them, and score_case matches on exact
        # strings, so reporting a template name as an issue label would inflate
        # false positives.  The observation set stays empty and measured instead.
        base["detectedIssues"] = []
        base["observationBasis"] = ("none:no_ground_truth_category_mapping_for_invariant_templates")
    elif states and all(state in {"passed", "unavailable"} for state in states) \
            and base["executedAssertionCount"] > 0:
        base["state"] = "completed"
        base["outcome"] = "passed"
        base["detectedIssues"] = []
        base["observationBasis"] = "none:all_executed_invariants_held"
    else:
        base["state"] = "unavailable"
        base["reason"] = "no_invariant_assertion_executed"
    base["confirmedVulnerability"] = False
    base["interpretation"] = ("role-aware protocol assertions executed against locally compiled "
                              "source; a violated invariant is an observed failure of that property, "
                              "not a confirmed vulnerability")
    return base


def run_case(case_id: str, *, layers: tuple[str, ...] = ("ir-reconcile", "invariants")) -> dict[str, Any]:
    """Produce every requested layer for one benchmark case."""
    case = _read_case(case_id)
    solc_version = str(case["groundTruth"].get("solcVersion") or "")
    compiler_metadata: dict[str, Any] = {}
    try:
        _, compiler_metadata = _compiler_for(case)
    except Exception as error:
        reason = f"compiler_unavailable:{type(error).__name__}:{str(error)[:160]}"
        written = {}
        for layer, filename in (("ir-reconcile", "ir-reconcile.json"), ("invariants", "invariants.json")):
            if layer not in layers:
                continue
            payload = {"schemaVersion": 1, "caseId": case_id, "state": "failed",
                       "reason": reason, "detectedIssues": [],
                       "sourceSha256": case["sourceSha256"],
                       "sourceBundleSha256": _canonical_sha256({case["sourceName"]: case["sourceText"]}),
                       "compilerVersion": solc_version,
                       "executionBoundary": _local_execution_boundary(),
                       "generatedAt": _module("corpus_shards.py", "corpus_shards_clock").now()}
            _atomic_json(case["caseDir"] / filename, payload)
            written[layer] = "failed"
        return {"caseId": case_id, "layers": written, "state": "failed", "reason": reason}

    results: dict[str, Any] = {}
    for layer, filename in (("ir-reconcile", "ir-reconcile.json"), ("invariants", "invariants.json")):
        if layer not in layers:
            continue
        payload = (_ir_reconcile_evidence(case, compiler_metadata, solc_version)
                   if layer == "ir-reconcile"
                   else _invariants_evidence(case, compiler_metadata, solc_version))
        binding_error = _binding_error(case_id, case["sourceSha256"], solc_version,
                                       str(compiler_metadata.get("sha256") or ""),
                                       {**payload, "caseId": case_id,
                                        "sourceSha256": case["sourceSha256"],
                                        "compilerVersion": solc_version,
                                        "compilerArtifactSha256": compiler_metadata.get("sha256"),
                                        "executionBoundary": payload.get("executionBoundary")})
        if binding_error:
            # A layer that cannot prove which source it describes is discarded
            # rather than published; a failed run is recorded, not hidden.
            payload = {**payload, "state": "failed", "detectedIssues": [],
                       "reason": f"evidence_binding_invalid:{binding_error}",
                       "bindingError": binding_error}
        _atomic_json(case["caseDir"] / filename, payload)
        results[layer] = {"state": payload.get("state"),
                          "issues": len(payload.get("detectedIssues") or []),
                          "reason": payload.get("reason")}
    return {"caseId": case_id, "layers": results,
            "state": "completed" if any(row.get("state") == "completed" for row in results.values()) else "unavailable"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", dest="cases",
                        help="benchmark case id; repeatable")
    parser.add_argument("--all", action="store_true", help="process every benchmark case")
    parser.add_argument("--layers", default="ir-reconcile,invariants",
                        help="comma separated layers to produce")
    args = parser.parse_args(argv)
    layers = tuple(part.strip() for part in args.layers.split(",") if part.strip())
    unknown = set(layers) - {"ir-reconcile", "invariants"}
    if unknown:
        parser.error(f"unknown layer: {','.join(sorted(unknown))}")
    case_ids = args.cases or (_case_ids() if args.all else [])
    if not case_ids:
        parser.error("provide --case or --all")
    summary = {"layers": list(layers), "caseCount": len(case_ids), "cases": []}
    for index, case_id in enumerate(case_ids, 1):
        print(f"[{index}/{len(case_ids)}] {case_id} ...", flush=True)
        try:
            outcome = run_case(case_id, layers=layers)
        except Exception as error:
            outcome = {"caseId": case_id, "state": "failed",
                       "reason": f"{type(error).__name__}:{str(error)[:160]}", "layers": {}}
        summary["cases"].append(outcome)
        for layer, row in outcome.get("layers", {}).items():
            print(f"    {layer}: {row.get('state')} issues={row.get('issues')}"
                  + (f" reason={row.get('reason')}" if row.get("reason") else ""), flush=True)
    counts: dict[str, dict[str, int]] = {}
    for outcome in summary["cases"]:
        for layer, row in outcome.get("layers", {}).items():
            counts.setdefault(layer, {})
            counts[layer][str(row.get("state"))] = counts[layer].get(str(row.get("state")), 0) + 1
    summary["stateCounts"] = counts
    print(json.dumps(summary["stateCounts"], sort_keys=True))
    # A run in which nothing was produced at all is a failure, not a quiet success.
    produced = sum(total for layer in counts.values() for state, total in layer.items()
                   if state == "completed")
    return 0 if produced else 1


if __name__ == "__main__":
    raise SystemExit(main())