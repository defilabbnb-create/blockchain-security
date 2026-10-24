#!/usr/bin/env python3
"""变异测试：证明看门狗的回归测试真的有鉴别力。

按 .cursor/rules/silent-wrong-value-review.mdc 的要求：
「仅靠代码审查不够，必须有可运行的回归测试固化这个边界。」
所以这里故意把每个关键判定改坏，逐个确认**预期的那个测试**会失败。

判据用「预期的测试名必须出现在失败清单里」，而不是笼统的「测试失败了」：
  - 笼统判据会把「因为别的原因失败」误当成捕获
  - 精确到测试名，才能证明这条边界真的被这条用例守着

如果某个变异改坏了代码但预期的测试仍然通过，说明那条测试是空壳，
必须补测试或修实现 —— 两者都不能放过。

实现要点：变异在**临时副本**上做，不动工作副本。
早期版本直接改工作副本再还原，结果并行编辑被还原覆盖 —— 两次踩坑，
现在用隔离目录从根上避免。
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "tunnel_serveo_watchdog.py"
TEST = "tests.test_tunnel_serveo_watchdog"

# (变异名, 原始片段, 改坏后的片段, 预期失败的测试名)
MUTATIONS = [
    (
        "任何状态码都当 alive（最典型的静默错值）",
        '    if result.status in ALIVE_CODES:\n        return "alive"',
        '    if result.status is not None:\n        return "alive"',
        "test_502_is_dead",
    ),
    (
        "expired 不作废域名（域名还在就算活）",
        "                state.alive = False\n                state.expired = True",
        "                state.expired = True",
        "test_expired_after_forwarding_marks_domain_not_alive",
    ),
    (
        "展示层无视 verdict，失效域名也当可用地址",
        '    if verdict == "alive" and not stale:\n        lines.append(f"兜底地址      : {serve.get(\'url\')}")',
        '    if True:\n        lines.append(f"兜底地址      : {serve.get(\'url\')}")',
        "test_dead_does_not_present_stale_domain_as_usable",
    ),
    (
        "过期结论仍当可用（缓存冒充实时）",
        "    if verdict == \"alive\" and not stale:",
        "    if verdict == \"alive\":",
        "test_alive_but_stale_is_not_shown_as_usable",
    ),
    (
        "is_stale 永远返回 False（缓存永不过期）",
        "    age = (now - stamp).total_seconds()\n    return age > max_age",
        "    age = (now - stamp).total_seconds()\n    return False",
        "test_alive_but_stale_is_not_shown_as_usable",
    ),
    (
        "502 归类成 alive",
        '    if result.status in DEAD_CODES:\n        return "dead"',
        '    if result.status in DEAD_CODES:\n        return "alive"',
        "test_502_is_dead",
    ),
    (
        "不设阈值，永远重启",
        "    if failures < threshold:\n        return Decision(",
        "    if False:\n        return Decision(",
        "test_dead_below_threshold_does_not_restart",
    ),
    (
        "忽略冷却期（重启风暴）",
        "        if 0 <= elapsed < cooldown:",
        "        if False:",
        "test_cooldown_blocks_restart",
    ),
    (
        "忽略每小时频率上限",
        "    if len(history) >= hourly_cap:",
        "    if False:",
        "test_hourly_cap_blocks_restart",
    ),
    (
        "重启失败被报成成功",
        '        serve["restartSucceeded"] = bool(ok)',
        '        serve["restartSucceeded"] = True',
        "test_failed_restart_is_reported_not_swallowed",
    ),
    (
        "重建后没拿到新域名却报 alive",
        '                serve["verdict"] = "unavailable"\n'
        '                serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1\n'
        '                serve["reason"] = "重建会话后未拿到新域名"',
        '                serve["verdict"] = "alive"\n'
        '                serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1\n'
        '                serve["reason"] = "重建会话后未拿到新域名"',
        "test_restart_without_new_domain_is_unavailable_not_alive",
    ),
]


def run_tests(workdir: Path):
    """在指定目录里跑回归测试。

    目录结构须与仓库一致（scripts/ 与 tests/ 同级），
    因为测试用 `parents[1] / 'scripts'` 定位被测模块。
    """
    result = subprocess.run(
        [sys.executable, "-m", "unittest", TEST],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def _make_isolated(tmp: Path) -> Path:
    """搭一个隔离的仓库副本：只放被测模块与对应测试。"""
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp / "tests").mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE, tmp / "scripts" / SOURCE.name)
    shutil.copy2(ROOT / "tests" / "test_tunnel_serveo_watchdog.py",
                 tmp / "tests" / "test_tunnel_serveo_watchdog.py")
    (tmp / "tests" / "__init__.py").write_text("", encoding="utf-8")
    return tmp / "scripts" / SOURCE.name


def main():
    original = SOURCE.read_text(encoding="utf-8")
    problems = []
    detected = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        workdir = tmp
        target = _make_isolated(tmp)

        # 基线：未变异时测试必须全绿，否则谈不上鉴别力。
        code, output = run_tests(workdir)
        if code != 0:
            print("基线失败：未变异状态下测试就没过，先修测试再谈变异")
            print(output[-3000:])
            return 1
        print("基线通过（未变异时全绿）")
        print()

        for name, old, new, expected_test in MUTATIONS:
            if old not in original:
                print(f"[ANCHOR-MISS] {name}")
                print("             锚点没匹配到实现，变异未被应用")
                problems.append(f"{name}（锚点未匹配）")
                continue

            # 只改隔离副本，工作副本全程不动。
            target.write_text(original.replace(old, new, 1), encoding="utf-8")
            code, output = run_tests(workdir)
            failed = set(re.findall(r"^(?:FAIL|ERROR): (\S+)", output, re.M))

            if code == 0:
                print(f"[SURVIVED] {name}")
                print("           测试全绿 —— 缺少覆盖该边界的回归测试")
                problems.append(f"{name}（变异存活）")
                continue

            if expected_test in failed:
                detected += 1
                print(f"[CAUGHT] {name}")
                print(f"          预期测试 {expected_test} 已失败（共 {len(failed)} 条失败）")
            else:
                print(f"[MISDIRECTED] {name}")
                print(f"             测试失败了，但预期测试 {expected_test} 没在失败清单里")
                print(f"             实际失败：{sorted(failed) or '（无解析到）'}")
                problems.append(f"{name}（失败原因不对应）")

            # 复位隔离副本，保证下一个变异从原始代码出发。
            target.write_text(original, encoding="utf-8")

    # 确认工作副本没被动过。
    if SOURCE.read_text(encoding="utf-8") != original:
        print("工作副本被改动了！隔离机制失效。")
        return 1

    print()
    code, output = run_tests(ROOT)
    print(f"工作副本测试退出码：{code}")
    if code != 0:
        print("工作副本测试失败！")
        print(output[-2000:])
        return 1

    print(f"变异总数 {len(MUTATIONS)}，被精确捕获 {detected}")
    if problems:
        print("需要处理：")
        for item in problems:
            print(f"  - {item}")
        return 1
    print("全部变异均被对应测试精确捕获。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
