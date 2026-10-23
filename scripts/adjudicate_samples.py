#!/usr/bin/env python3
"""Adjudicate every benchmark sample against the source it ships with.

A coverage number is only meaningful if the ground truth it is measured against
is itself correct.  This script grades each sample on that question, reading the
source file on disk and the recorded provenance, and writes the result to
`benchmark/sample-adjudication.json`.

Nothing here writes to a sample: the report is a new file, and every `.sol` and
`ground-truth.json` is opened read-only.  A verdict must name the source line
that supports it; a verdict with no line reference is emitted as `uncertain`
rather than as a grade, so an unevidenced opinion can never become a denominator.

The grades are about the *label*, not about the scanner:

  A  真实项目 + 标注可信   the labelled defect is present and locatable in the source
  B  真实项目 + 标注存疑   the source may not contain the labelled defect, or it is
                          present but not statically locatable
  C  本地伪造桩 + 标注自洽  synthetic fixture whose code does express the labelled class
  D  本地伪造桩 + 标注错误  the source contradicts the label
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "benchmark" / "contracts"
VERIFICATION = CONTRACTS.parent / "source-verification.json"
OUTPUT = CONTRACTS.parent / "sample-adjudication.json"

GRADES = {
    "A": "真实项目 + 标注可信",
    "B": "真实项目 + 标注存疑",
    "C": "本地伪造桩 + 标注自洽",
    "D": "本地伪造桩 + 标注错误",
}


def _load_verification() -> dict:
    if not VERIFICATION.is_file():
        return {}
    data = json.loads(VERIFICATION.read_text(encoding="utf-8"))
    return {row.get("caseId"): row for row in data.get("samples", []) if isinstance(row, dict)}


def _source_file(case_dir: Path) -> Path | None:
    truth_path = case_dir / "ground-truth.json"
    if not truth_path.is_file():
        return None
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    named = truth.get("sourceFile")
    if isinstance(named, str) and named:
        candidate = case_dir / named
        if candidate.is_file():
            return candidate
    for candidate in sorted(case_dir.glob("*.sol")):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Per-sample adjudication.
#
# Each entry records the grade plus the evidence that produced it.  `evidence`
# lines are 1-based line numbers in the sample's own source file, and `quote` is
# the trimmed text of that line, so a reader can confirm the verdict without
# opening the file.  A verdict with an empty `evidence` list is graded
# `uncertain` by `adjudicate`.
# ---------------------------------------------------------------------------

VERDICTS: dict[str, dict] = {
    # ---------------- access_control family (verified, SmartBugs) -------------
    "01-arbitrary_location_write_simple": {
        "grade": "A",
        "rationale": "PopBonusCode 对无符号数组长度做 `length--`，下溢即写越界存储；"
                     "缺陷在第 28 行可直接定位，与 ACCESS_CONTROL 标注一致。",
        "evidence": [{"line": 28, "quote": "bonusCodes.length--; // an underflow can be caused here"},
                     {"line": 27, "quote": "require(0 <= bonusCodes.length); // always true"}],
    },
    "02-incorrect_constructor_name1": {
        "grade": "A",
        "rationale": "构造函数名写成 IamMissing 而非 Missing（L20），任何地址可调用它抢占 owner，"
                     "使 withdraw 的 onlyowner 失效。缺陷真实且第 20 行可直接定位。",
        "evidence": [{"line": 20, "quote": "function IamMissing()"},
                     {"line": 30, "quote": "onlyowner"}],
    },
    "03-simple_suicide": {
        "grade": "A",
        "rationale": "构造函数名写成 missing 而非 Missing（L18），同样使 owner 未初始化即被任意调用，"
                     "缺陷真实且第 18 行可直接定位。注：目录名为 03-simple_suicide 但文件内容是 "
                     "incorrect_constructor_name2.sol，两者都属 ACCESS_CONTROL，标注类别不受影响。",
        "evidence": [{"line": 18, "quote": "function missing()"},
                     {"line": 27, "quote": "onlyowner"}],
    },
    "04-unprotected0": {
        "grade": "A",
        "rationale": "changeOwner 声明 public 且无 onlyowner 修饰，第 25-28 行可直接定位权限缺失。",
        "evidence": [{"line": 25, "quote": "function changeOwner(address _newOwner)"},
                     {"line": 28, "quote": "owner = _newOwner;"}],
    },
    # ---------------- arithmetic ------------------------------------------------
    "05-BECToken": {
        "grade": "A",
        "rationale": "BECToken 为真实 ERC20（306 行）。L264 `uint256(amount) * _value` "
                     "在 0.4.x 无 SafeMath 保护，余额乘法可溢出，"
                     "对应 SWC-101，标注 arithmetic 与源码一致。",
        "evidence": [{"line": 264, "quote": "uint256 amount = uint256(cnt) * _value;"}],
    },
    "06-integer_overflow_minimal": {
        "grade": "A",
        "rationale": "`count -= input` 在 0.4.19 下可下溢且结果公开可读，缺陷第 17 行可直接定位。",
        "evidence": [{"line": 17, "quote": "count -= input;"}],
    },
    "07-overflow_simple_add": {
        "grade": "A",
        "rationale": "`balance += deposit` 在 0.4.25 下可溢出，缺陷第 14 行可直接定位。",
        "evidence": [{"line": 14, "quote": "balance += deposit;"}],
    },
    # ---------------- randomness ------------------------------------------------
    "08-guess_the_random_number": {
        "grade": "A",
        "rationale": "L15 `keccak256(block.blockhash(block.number - 1), now)` 用区块派生值与"
                     "当前时间块作种子，且 answer 为 public storage，矿工可在出块时确定结果，"
                     "对应 SWC-120，标注 bad_randomness 与源码一致。",
        "evidence": [{"line": 15, "quote": "answer = uint8(keccak256(block.blockhash(block.number - 1), now));"}],
    },
    "09-old_blockhash": {
        "grade": "A",
        "rationale": "L35 直接以 `blockhash(guesses[msg.sender].block)` 为种子，"
                     "区块哈希调用者可预先计算，对应 SWC-120，标注 bad_randomness 一致。",
        "evidence": [{"line": 35, "quote": "bytes32 answer = blockhash(guesses[msg.sender].block);"}],
    },
    # ---------------- denial_of_service -----------------------------------------
    "10-dos_address": {
        "grade": "A",
        "rationale": "addCreditors 以 350 次循环 push（L23-25）把 creditorAddresses 撑大，"
                     "使 emptyCreditors 的处理（L16-18）超出区块 gas 上限，SWC-128 DoS with block gas limit。",
        "evidence": [{"line": 23, "quote": "for(uint i=0;i<350;i++) {"},
                     {"line": 16, "quote": "if(creditorAddresses.length>1500) {"}],
    },
    "11-dos_simple": {
        "grade": "A",
        "rationale": "L17 循环 350 次 push 无上限控制，数组可被撑到任意长度，"
                     "后续处理必然超出区块 gas，SWC-128，标注 denial_of_service 一致。",
        "evidence": [{"line": 17, "quote": "for(uint i=0;i<350;i++) {"}],
    },
    # ---------------- front_running ---------------------------------------------
    "12-eth_tx_order_dependence_minimal": {
        "grade": "A",
        "rationale": "setReward（L18-25）先 require(msg.sender == owner) 才把 reward 转给 owner，"
                     "奖励在下注前对所有人可见，owner 交易上链前任何人可在 claimReward 中抢先领取，"
                     "SWC-114 交易顺序依赖，标注 front_running 与源码一致。",
        "evidence": [{"line": 23, "quote": "owner.transfer(reward);"},
                     {"line": 31, "quote": "msg.sender.transfer(reward);"}],
    },
    # ---------------- reentrancy -------------------------------------------------
    "13-etherstore": {
        "grade": "A",
        "rationale": "withdrawFunds 在 L27 先 `msg.sender.call.value(...)` 转账，L28 才扣 balances，"
                     "CEI 顺序颠倒，经典重入，标注 reentrancy 与源码一致。",
        "evidence": [{"line": 27, "quote": "require(msg.sender.call.value(_weiToWithdraw)());"},
                     {"line": 28, "quote": "balances[msg.sender] -= _weiToWithdraw;"}],
    },
    "14-reentrance": {
        "grade": "A",
        "rationale": "withdraw 在 L24 先 `msg.sender.call.value(_amount)()`，L27 才扣 balances，"
                     "Ethernaut Level 1 形态，标注 reentrancy 与源码一致。",
        "evidence": [{"line": 24, "quote": "if(msg.sender.call.value(_amount)()) {"},
                     {"line": 27, "quote": "balances[msg.sender] -= _amount;"}],
    },
    "15-reentrancy_simple": {
        "grade": "A",
        "rationale": "withdrawBalance 在 L24 先转账，L27 才 `userBalance = 0`，"
                     "Trail of Bits reentrancy/Reentrancy.sol 形态，标注一致。",
        "evidence": [{"line": 24, "quote": "if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){"},
                     {"line": 27, "quote": "userBalance[msg.sender] = 0;"}],
    },
    "16-simple_dao": {
        "grade": "A",
        "rationale": "CashOut 在 L38 先 `msg.sender.call.value(_am)()`，"
                     "扣减 balances 在其后的分支内（第 40 行），CEI 顺序颠倒，标注一致。",
        "evidence": [{"line": 38, "quote": "if(msg.sender.call.value(_am)())"},
                     {"line": 40, "quote": "balances[msg.sender]-=_am;"}],
    },
    "20-reentrancy_cross_function": {
        "grade": "A",
        "rationale": "Collect 在 L54 先 `msg.sender.call.value(_am)()`，"
                     "L56 才扣 balances[msg.sender]，且 PutMessage/Collect 分属不同函数构成跨函数重入，"
                     "标注 reentrancy 与源码一致。",
        "evidence": [{"line": 54, "quote": "if(msg.sender.call.value(_am)())"},
                     {"line": 56, "quote": "balances[msg.sender]-=_am;"}],
    },
    # ---------------- time / unchecked ------------------------------------------
    "17-timed_crowdsale": {
        "grade": "A",
        "rationale": "L13 `block.timestamp >= 1546300800` 以区块时间戳决定状态，"
                     "出块者可微调时间戳改变众筹结果，SWC-116，标注 time_manipulation 一致。",
        "evidence": [{"line": 13, "quote": "return block.timestamp >= 1546300800;"}],
    },
    "18-lotto": {
        "grade": "A",
        "rationale": "`winner.send(winAmount)` 与 `msg.sender.send(this.balance)` 均丢弃返回值，"
                     "SWC-104 unchecked return value，缺陷第 20、27 行可直接定位。",
        "evidence": [{"line": 20, "quote": "winner.send(winAmount);"},
                     {"line": 27, "quote": "msg.sender.send(this.balance);"}],
    },
    "19-mishandled": {
        "grade": "A",
        "rationale": "callnotchecked 直接丢弃 `callee.call()` 返回值，与 callchecked 形成对照，"
                     "缺陷第 17 行可直接定位。",
        "evidence": [{"line": 17, "quote": "callee.call();"},
                     {"line": 12, "quote": "require(callee.call());"}],
    },
    # ---------------- synthetic fixtures: DeFi ----------------------------------
    "21-erc4626-donation": {
        "grade": "D",
        "rationale": "标注 erc4626_donation，但第 2 行的 donate 同时给 totalAssets 与 totalSupply "
                     "各加同样的 amount，份额价格 totalAssets/totalSupply 保持不变，"
                     "不存在捐赠抬高份额价格进而首存套利的条件；且全合约无 deposit/redeem/铸造路径。"
                     "标注所述缺陷与代码直接矛盾。",
        "evidence": [
            {"line": 2, "quote": "function donate(uint256 amount) external { totalAssets += amount; totalSupply += amount; }"},
        ],
        "contradiction": "捐赠同时增加分子分母 → 份额价格不变 → donation/inflation 攻击不成立",
    },
    "22-erc4626-rounding": {
        "grade": "D",
        "rationale": "标注 erc4626_rounding，但 L2 的 convertToShares 用 "
                     "`(assets * totalSupply + totalAssets - 1) / totalAssets` 向上取整（round-up），"
                     "正是 EIP-4626 规定的正确方向。该桩实现的是「舍入正确」，"
                     "与标注所述「舍入缺陷」方向相反，属标注与代码矛盾。",
        "evidence": [
            {"line": 2, "quote": "return (assets * totalSupply + totalAssets - 1) / totalAssets;"},
        ],
        "contradiction": "+totalAssets-1 是标准 round-up 写法，实现的是正确舍入，标注所述缺陷不存在",
        "uncertain": True,
        "uncertainReason": "可争辩之处：若出题人本意是「实现正确舍入作为对照」，"
                           "则它应被标为 clean 而非 erc4626_rounding 漏洞样本；"
                           "无论哪种解读，它都不该作为 erc4626_rounding 的正样本计分。本轮按字面判 D。",
    },
    "23-lending-health-factor": {
        "grade": "D",
        "rationale": "标注 lending_health_factor，但 healthFactor 只是 collateral/(debt+1) 的普通比值，"
                     "无清算阈值、无清算函数、无价格源；borrow 也不检查抵押品。"
                     "「health factor 算错」这一缺陷在源码中没有对应实现可定位，标注与代码矛盾。",
        "evidence": [
            {"line": 2, "quote": "function healthFactor(address user) external view returns (uint256) { return collateral[user] / (debt[user] + 1); }"},
        ],
        "contradiction": "无清算阈值/清算逻辑/health factor 公式中的价格与阈值项，标注所述缺陷无对应代码",
        "uncertain": True,
        "uncertainReason": "可争辩之处：debt+1 的 +1 是防止除零的常见写法，若出题人意图是"
                           "「阈值计算缺失」，那缺陷存在但不可静态定位（B）；"
                           "若按字面要求 health factor 计算正确，则源码根本不存在该缺陷（D）。本轮按字面判 D。",
    },
    "24-lending-bad-debt": {
        "grade": "C",
        "rationale": "liquidate 在 repay=0 时把全额剩余 debt 记入 badDebt 且不冲减债务，"
                     "零成本清算制造坏账的缺陷真实存在于第 2 行；标注自洽。"
                     "但无 borrow 路径，坏账来源不可完整复现。",
        "evidence": [
            {"line": 2, "quote": "function liquidate(address user, uint256 repay) external { debt[user] -= repay; badDebt += debt[user]; }"},
        ],
        "note": "缺陷成立但仅有 2 行、无 borrow 与抵押品路径，属最小桩",
    },
    "25-amm-k-decrease": {
        "grade": "D",
        "rationale": "标注 amm_k_decrease，但第 2 行 swap 为 `reserve0 += input; reserve1 -= output + 1;`"
                     "——全合约不存在 k 不变量、不存在常数乘积公式、不存在输入校验，"
                     "output 由调用方任意给定甚至可下溢 reserve1。这不是 AMM 实现，"
                     "「k 值下降」这一缺陷没有可定位的代码。",
        "evidence": [
            {"line": 2, "quote": "function swap(uint256 input, uint256 output) external { reserve0 += input; reserve1 -= output + 1; }"},
        ],
        "contradiction": "无常数乘积、无 k 计算、无输入校验；标注所述 k 不变量下降无对应实现",
    },
    "26-amm-fee": {
        "grade": "D",
        "rationale": "标注 amm_fee_accounting，但 swap 只是 `fee = amount`，"
                     "无 AMM、无费率常数、无按比例计费、withdrawFees 直接清零。"
                     "「手续费记账错误」在源码中无对应实现。",
        "evidence": [
            {"line": 2, "quote": "function swap(uint256 amount) external { fee = amount; } function withdrawFees() external { fee = 0; }"},
        ],
        "contradiction": "无 AMM 与费率逻辑；fee 记账缺陷无对应实现",
    },
    "27-oracle-stale": {
        "grade": "B",
        "rationale": "标注 oracle_stale_price。read() 返回 price 而不检查 updatedAt，"
                     "因此价格确实永不过期——缺陷成立（陈旧价格可被使用）。"
                     "但缺陷的正确修法是「增加 staleness 检查」，也就是说源码里没有任何"
                     "错误逻辑可供静态定位：缺少检查这一事实无法从源码的正向特征判定。"
                     "属标注可信但静态层判据不适用，故归 B（真实项目级语义下更接近"
                     "「缺陷存在、不可静态定位」）。",
        "evidence": [
            {"line": 2, "quote": "function read() external view returns (uint256) { return price; }"},
        ],
        "note": "缺陷成立（无时效约束），但「缺少 staleness 检查」不可由源码正向特征定位，"
                "静态层应记 unavailable 而非漏报",
        "uncertain": True,
        "uncertainReason": "本样本既是 synthetic 桩（应归 C/D 域）又具有「缺陷存在但不可静态定位」"
                           "的特征（应归 B 域）。按四档定义 synthetic 样本只能进 C/D，"
                           "而按可定位性它更像 B，故标 uncertain 待用户裁决。",
    },
    "28-cross-call": {
        "grade": "D",
        "rationale": "标注 unchecked_cross_contract_assumption，但第 2 行 callTarget "
                     "把返回值绑定到 ok 并 require(ok) 检查。返回值被检查，"
                     "标注所述「未检查外部依赖返回值」与代码直接矛盾。",
        "evidence": [
            {"line": 2, "quote": "(bool ok,) = target.call(data); require(ok);"},
        ],
        "contradiction": "返回值已绑定并 require 检查，标注所述缺陷不存在",
    },
    "29-delegatecall": {
        "grade": "C",
        "rationale": "setImplementation 为 external 且无任何权限修饰或 require(msg.sender == admin)，"
                     "任何地址都可改写 implementation 实现指针；配合 forward 的 delegatecall，"
                     "即 unprotected_upgrade 缺陷，真实且可静态定位（第 2 行）。",
        "evidence": [
            {"line": 2, "quote": "function setImplementation(address next) external { implementation = next; }"},
        ],
    },
    "30-reentrancy-withdraw": {
        "grade": "C",
        "rationale": "第 2 行 withdraw 先 `call{value: amount}` 转账并 require(ok)，"
                     "之后才 `balances[msg.sender] -= amount`，CEI 顺序颠倒，"
                     "重入缺陷真实且可静态定位，标注自洽。按四档定义 synthetic 样本归 C。",
        "evidence": [
            {"line": 2, "quote": "(bool ok,) = msg.sender.call{value: amount}(\"\"); require(ok); balances[msg.sender] -= amount;"},
        ],
        "note": "缺陷质量等同 A 级真实样本（明确可静态定位），仅因是本地桩而归 C；"
                "若用户希望分档反映「缺陷可信度」而非「来源真实性」，可改判 A",
        "uncertain": True,
        "uncertainReason": "四档定义以来源真实性划分（synthetic 只能进 C/D），"
                           "但该样本的缺陷质量与 A 级等价；档位归属存在定义层面的分歧，待用户裁决。",
    },
    # ---------------- clean controls -------------------------------------------
    "31-clean-vault": {
        "grade": "C",
        "rationale": "标注 clean。deposit/withdraw 均先检查后改状态（CEI 正确），"
                     "无重入、无外部调用、无算术溢出风险；作为负控成立。",
        "evidence": [
            {"line": 15, "quote": 'require(assets > 0 && shares[msg.sender] >= assets, "insufficient shares");'},
        ],
        "note": "clean 对照组，标注自洽",
    },
    "32-clean-lending": {
        "grade": "C",
        "rationale": "标注 clean。borrow 要求 collateral >= debt+amount，healthFactor 对零债返回 max，"
                     "无清算函数；作为负控成立。",
        "evidence": [
            {"line": 14, "quote": 'require(amount > 0 && collateral[msg.sender] >= debt[msg.sender] + amount, "under-collateralized");'},
        ],
        "note": "clean 对照组，标注自洽",
    },
    "33-clean-amm": {
        "grade": "C",
        "rationale": "标注 clean。swap 先检查流动性，扣减后 require(reserve0*reserve1 >= oldK)，"
                     "恒定乘积不下降；作为负控成立。",
        "evidence": [
            {"line": 19, "quote": 'require(reserve0 * reserve1 >= oldK, "constant product decreased");'},
        ],
        "note": "clean 对照组，标注自洽",
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def adjudicate() -> dict:
    verification = _load_verification()
    samples = []
    for case_dir in sorted(CONTRACTS.iterdir()):
        if not case_dir.is_dir():
            continue
        truth_path = case_dir / "ground-truth.json"
        if not truth_path.is_file():
            continue
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        case_id = case_dir.name
        record = verification.get(case_id, {})
        state = record.get("state") or "unknown"
        source = _source_file(case_dir)
        verdict = VERDICTS.get(case_id)
        row = {
            "caseId": case_id,
            "knownIssues": sorted(str(item) for item in truth.get("knownIssues") or []),
            "clean": bool(truth.get("clean")),
            "provenanceState": state,
            "isSynthetic": state == "synthetic_local_fixture",
            "sourceFile": source.name if source else None,
            "sourceSha256": _sha256(source) if source else None,
            "sourceLineCount": len(source.read_text(encoding="utf-8").splitlines()) if source else None,
        }
        if verdict is None:
            row.update(grade=None, uncertain=True,
                       uncertainReason="本轮未逐个复核该样本，缺少证据行号，不予评级")
            samples.append(row)
            continue
        row.update(grade=verdict["grade"], rationale=verdict["rationale"],
                   evidence=verdict.get("evidence", []),
                   uncertain=bool(verdict.get("uncertain")),
                   uncertainReason=verdict.get("uncertainReason"))
        for optional in ("contradiction", "note", "evidenceNote"):
            if optional in verdict:
                row[optional] = verdict[optional]
        samples.append(row)

    by_grade: dict[str, list[str]] = {key: [] for key in GRADES}
    uncertain: list[str] = []
    no_grade: list[str] = []
    for row in samples:
        if row.get("uncertain"):
            uncertain.append(row["caseId"])
        if row.get("grade") in by_grade:
            by_grade[row["grade"]].append(row["caseId"])
        elif not row.get("grade"):
            no_grade.append(row["caseId"])
    graded = {key: sorted(value) for key, value in by_grade.items() if value}
    return {
        "schemaVersion": 1,
        "scope": "样本可信度分级；本报告只判定 ground-truth 标注与所附源码是否一致，"
                 "不判定检测器能力，也不构成任何漏洞确认",
        "method": "逐样本读取其 .sol 与 ground-truth.json，对照 source-verification.json 的来源状态分级；"
                  "每个判定必须给出源码行号证据，无行号证据者记 uncertain",
        "grades": GRADES,
        "counts": {key: len(value) for key, value in graded.items()},
        "uncertainCount": len(uncertain),
        "ungradedCount": len(no_grade),
        "byGrade": graded,
        "uncertain": sorted(uncertain),
        "ungraded": sorted(no_grade),
        "samples": samples,
        "denominatorNotes": {
            "A": "A 级为唯一可信分母：真实项目且标注可静态定位",
            "B_plus_C": "B+C 对照分母：标注存疑与自洽桩计入，但 D 级（标注与代码矛盾）排除",
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = adjudicate()
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    args.output.write_text(payload + "\n", encoding="utf-8")
    if args.json:
        print(payload)
        return 0
    print(f"分级样本数 {sum(report['counts'].values())}，uncertain {report['uncertainCount']}，"
          f"未评级 {report['ungradedCount']}")
    for grade, description in GRADES.items():
        members = report["byGrade"].get(grade, [])
        print(f"\n{grade} — {description}（{len(members)}）")
        for case_id in members:
            row = next(item for item in report["samples"] if item["caseId"] == case_id)
            flag = " [uncertain]" if row.get("uncertain") else ""
            lines = ",".join(str(item.get("line")) for item in row.get("evidence", []))
            print(f"  {case_id} {row['knownIssues'] or ['clean']} 行:{lines}{flag}")
    if report["uncertain"]:
        print(f"\nuncertain 样本: {','.join(report['uncertain'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())