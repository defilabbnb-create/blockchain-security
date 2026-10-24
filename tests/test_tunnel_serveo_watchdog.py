"""serveo 兜底看门狗必须诚实报告状态，不能产出「看起来成功但语义错误」的结果。

背景（本机实测）：serveo.net 会单方面回收免费 SSH 反向转发，而 **ssh 进程
仍然活着**，launchd 的 KeepAlive 因此不会重启它，随机域名也仍然留在日志里。
现场是「进程在 / 域名在 / 转发已死」，公网访问 502，进程级没有任何错误信号。

旧 status.sh 用 `grep -oE 'https://[a-z0-9.-]+serveousercontent.com' | tail -1`
取域名，会把一个已经过期的域名当成「兜底地址」展示 —— 这正是本规则要防的
「状态合法但语义错误」。

本文件按本项目的静默错值审查标准固定以下行为：

  1. 日志解析必须区分「分配过域名」与「该域名当前仍有效」
  2. 探测归类必须双向正确：死的不能报 alive，活的不被误杀
  3. 拿不准的状态必须报 unknown，不能往 alive 靠
  4. 只有验证通过的域名才能被当成「可用兜底地址」展示
  5. 重启决策必须有阈值、冷却期与频率上限，不能变成重启风暴
  6. 状态文件损坏时诚实退回初始状态，不能崩也不能编造
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import tunnel_serveo_watchdog as W


def _ts(minutes_ago=0):
    return (datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc) - timedelta(minutes=minutes_ago))


class FakeClock:
    """会推进的假时钟。

    常量时钟会让等待循环永不退出（deadline 恒不大于 now），
    所以每次读取都前进固定步长，让循环能收敛。
    """

    def __init__(self, start=0.0, step=10.0):
        self.now = start
        self.step = step

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


class ParseLogTests(unittest.TestCase):
    """日志解析：域名分配 vs 域名有效性是两件事。"""

    def test_forwarding_line_marks_domain_alive(self):
        log = (
            "\x1b[32mForwarding HTTP traffic from "
            "https://abc123-82-110-234-120.serveousercontent.com\x1b[0m\n"
        )
        state = W.parse_serveo_log(log)
        self.assertEqual(state.domain, "abc123-82-110-234-120.serveousercontent.com")
        self.assertTrue(state.alive)
        self.assertFalse(state.expired)
        self.assertEqual(state.forwards, 1)

    def test_expired_after_forwarding_marks_domain_not_alive(self):
        """核心场景：域名还在日志里，但转发已被 serveo 回收。"""
        log = (
            "\x1b[32mForwarding HTTP traffic from "
            "https://abc123-82-110-234-120.serveousercontent.com\x1b[0m\n"
            "\x1b[33mPort forwarding for abc123-82-110-234-120.serveousercontent.com expired\x1b[0m\n"
        )
        state = W.parse_serveo_log(log)
        self.assertEqual(state.domain, "abc123-82-110-234-120.serveousercontent.com")
        self.assertFalse(state.alive, "expired 之后域名不能再算有效")
        self.assertTrue(state.expired)

    def test_closed_connection_invalidates_current_domain(self):
        log = (
            "\x1b[32mForwarding HTTP traffic from "
            "https://abc123-82-110-234-120.serveousercontent.com\x1b[0m\n"
            "\x1b[33mConnection to serveo.net closed by remote host.\x1b[0m\n"
        )
        state = W.parse_serveo_log(log)
        self.assertFalse(state.alive)

    def test_new_forwarding_after_expired_revives_alive(self):
        """顺序语义：expired 之后又有新的 Forwarding，说明是新的会话。"""
        log = (
            "\x1b[32mForwarding HTTP traffic from "
            "https://old-82-110-234-120.serveousercontent.com\x1b[0m\n"
            "\x1b[33mPort forwarding for old-82-110-234-120.serveousercontent.com expired\x1b[0m\n"
            "\x1b[32mForwarding HTTP traffic from "
            "https://new-82-110-234-120.serveousercontent.com\x1b[0m\n"
        )
        state = W.parse_serveo_log(log)
        self.assertEqual(state.domain, "new-82-110-234-120.serveousercontent.com")
        self.assertTrue(state.alive)
        self.assertEqual(state.forwards, 2)

    def test_expired_of_older_domain_does_not_kill_newer_domain(self):
        """边界：过期的是旧域名，不能误伤当前域名。

        这是「一个结果套到另一个结果上」的经典坑：
        日志里旧域名的 expired 行出现在新域名 Forwarding 之前，
        顺序解析必须保证最终 alive=True。
        """
        log = (
            "\x1b[32mForwarding HTTP traffic from "
            "https://new-82-110-234-120.serveousercontent.com\x1b[0m\n"
            "\x1b[33mPort forwarding for old-82-110-234-120.serveousercontent.com expired\x1b[0m\n"
        )
        state = W.parse_serveo_log(log)
        self.assertEqual(state.domain, "new-82-110-234-120.serveousercontent.com")
        self.assertTrue(state.alive, "别的域名的 expired 不能作废当前域名")
        self.assertFalse(state.expired)

    def test_empty_log_yields_no_domain(self):
        state = W.parse_serveo_log("")
        self.assertIsNone(state.domain)
        self.assertFalse(state.alive)

    def test_noise_only_log_yields_no_domain(self):
        """边界：日志只有噪声，不能编造出域名。"""
        state = W.parse_serveo_log("Pseudo-terminal will not be allocated because stdin is not a terminal.\n")
        self.assertIsNone(state.domain)
        self.assertFalse(state.alive)


class ClassifyProbeTests(unittest.TestCase):
    """探测归类：双向都不能错。"""

    def test_401_means_alive_because_request_reached_local_proxy(self):
        """无口令探测返回 401 反而是「隧道通」的证据。"""
        self.assertEqual(W.classify_probe(W.ProbeResult(status=401)), "alive")

    def test_200_is_alive(self):
        self.assertEqual(W.classify_probe(W.ProbeResult(status=200)), "alive")

    def test_403_is_alive_because_host_check_rejected(self):
        """应用侧 Host 校验拒绝，说明流量确实到了本机。"""
        self.assertEqual(W.classify_probe(W.ProbeResult(status=403)), "alive")

    def test_502_is_dead(self):
        self.assertEqual(W.classify_probe(W.ProbeResult(status=502)), "dead")

    def test_503_and_504_are_dead(self):
        self.assertEqual(W.classify_probe(W.ProbeResult(status=503)), "dead")
        self.assertEqual(W.classify_probe(W.ProbeResult(status=504)), "dead")

    def test_connection_error_is_dead(self):
        result = W.ProbeResult(status=None, error="URLError: <urlopen error timed out>")
        self.assertEqual(W.classify_probe(result), "dead")

    def test_unexpected_status_is_unknown_not_alive(self):
        """拿不准就必须说 unknown —— 不能往 alive 靠。"""
        self.assertEqual(W.classify_probe(W.ProbeResult(status=404)), "unknown")
        self.assertEqual(W.classify_probe(W.ProbeResult(status=500)), "unknown")
        self.assertEqual(W.classify_probe(W.ProbeResult(status=200 + 100)), "unknown")

    def test_no_status_no_error_is_unknown(self):
        self.assertEqual(W.classify_probe(W.ProbeResult(status=None, error=None)), "unknown")


class DecisionTests(unittest.TestCase):
    """重启决策：阈值、冷却、频率上限。"""

    def _serve(self, **kw):
        base = {
            "verdict": "dead",
            "consecutiveFailures": 5,
            "lastRestartAt": None,
            "restartHistory": [],
        }
        base.update(kw)
        return base

    def test_alive_never_restarts(self):
        decision = W.decide_action(
            self._serve(verdict="alive", consecutiveFailures=0),
            W.LogState(domain="d.serveousercontent.com", alive=True),
            _ts(),
        )
        self.assertEqual(decision.action, "none")

    def test_dead_below_threshold_does_not_restart(self):
        decision = W.decide_action(
            self._serve(consecutiveFailures=1),
            W.LogState(domain="d.serveousercontent.com"),
            _ts(),
        )
        self.assertEqual(decision.action, "none")
        self.assertIn("未达阈值", decision.reason)

    def test_dead_at_threshold_restarts(self):
        decision = W.decide_action(
            self._serve(consecutiveFailures=W.DEAD_THRESHOLD),
            W.LogState(domain="d.serveousercontent.com"),
            _ts(),
        )
        self.assertEqual(decision.action, "restart")

    def test_unknown_needs_higher_threshold_than_dead(self):
        """不确定信号比明确死信号更保守：阈值必须更高。"""
        self.assertGreater(W.UNKNOWN_THRESHOLD, W.DEAD_THRESHOLD)
        decision = W.decide_action(
            self._serve(verdict="unknown", consecutiveFailures=W.DEAD_THRESHOLD),
            W.LogState(domain="d.serveousercontent.com"),
            _ts(),
        )
        self.assertEqual(decision.action, "none", "unknown 在 dead 阈值处不该重启")

    def test_cooldown_blocks_restart(self):
        decision = W.decide_action(
            self._serve(consecutiveFailures=99, lastRestartAt=W._iso(_ts(1))),
            W.LogState(domain="d.serveousercontent.com"),
            _ts(),
        )
        self.assertEqual(decision.action, "none")
        self.assertIn("冷却", decision.reason)

    def test_hourly_cap_blocks_restart(self):
        history = [W._iso(_ts(minutes_ago=i)) for i in range(W.RESTART_HOURLY_CAP)]
        decision = W.decide_action(
            self._serve(consecutiveFailures=99, restartHistory=history),
            W.LogState(domain="d.serveousercontent.com"),
            _ts(),
        )
        self.assertEqual(decision.action, "none")
        self.assertIn("上限", decision.reason)

    def test_no_domain_restarts_immediately(self):
        """压根没域名说明 serveo job 没起来，等阈值没有意义。"""
        decision = W.decide_action(
            self._serve(consecutiveFailures=0),
            W.LogState(domain=None),
            _ts(),
        )
        self.assertEqual(decision.action, "restart")

    def test_stale_restart_history_outside_hour_does_not_block(self):
        """边界：超过一小时的旧重启记录不能继续占用频率上限。"""
        history = [W._iso(_ts(minutes_ago=90)) for _ in range(W.RESTART_HOURLY_CAP)]
        decision = W.decide_action(
            self._serve(consecutiveFailures=99, restartHistory=history),
            W.LogState(domain="d.serveousercontent.com"),
            _ts(),
        )
        self.assertEqual(decision.action, "restart")


class StateFileTests(unittest.TestCase):
    """状态文件：损坏要诚实退回，不能崩也不能编造。"""

    def test_missing_file_returns_blank_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = W.load_state(Path(tmp) / "nope.json")
        self.assertEqual(state["serveo"]["verdict"], "unavailable")
        self.assertIsNone(state["serveo"]["url"])

    def test_corrupt_json_returns_blank_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("{not json at all", encoding="utf-8")
            state = W.load_state(path)
        self.assertEqual(state["serveo"]["verdict"], "unavailable")
        self.assertIsNone(state["serveo"]["domain"])

    def test_partial_state_is_completed_with_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({"serveo": {"verdict": "dead"}}), encoding="utf-8")
            state = W.load_state(path)
        self.assertEqual(state["serveo"]["verdict"], "dead")
        self.assertIn("lastDecisionReason", state["serveo"])
        self.assertIn("cloudflare", state)


class RunOnceTests(unittest.TestCase):
    """端到端一轮：注入假的探测/重启，不碰真网络。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.serve_log = self.tmp / "serveo.log"
        self.state_file = self.tmp / "state.json"
        self.paths = {"serve_log": self.serve_log, "state_file": self.state_file}
        self.addCleanup(self._tmp.cleanup)

    def _write_log(self, text):
        self.serve_log.write_text(text, encoding="utf-8")

    def _probe_map(self, mapping, default=None):
        """按 URL 结尾返回预置结果。"""
        def probe(url):
            for suffix, result in mapping.items():
                if url.endswith(suffix):
                    return result
            return default if default is not None else W.ProbeResult(status=404)
        return probe

    def test_alive_domain_is_reported_alive_and_not_restarted(self):
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://good-82-110-234-120.serveousercontent.com\n"
        )
        restarts = []
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "good-82-110-234-120.serveousercontent.com": W.ProbeResult(status=401),
                    "blksec.luckytad.vip": W.ProbeResult(status=401),
                }
            ),
            restart=lambda: restarts.append(1) or True,
        )
        self.assertEqual(state["serveo"]["verdict"], "alive")
        self.assertEqual(state["serveo"]["consecutiveFailures"], 0)
        self.assertIsNotNone(state["serveo"]["lastVerifiedAt"])
        self.assertEqual(restarts, [], "可用时不该重启")

    def test_expired_domain_with_502_is_dead_not_alive(self):
        """核心回归：日志里有域名但转发已死 —— 不能报 alive。"""
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://dead-82-110-234-120.serveousercontent.com\n"
            "Port forwarding for dead-82-110-234-120.serveousercontent.com expired\n"
        )
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "dead-82-110-234-120.serveousercontent.com": W.ProbeResult(status=502),
                    "blksec.luckytad.vip": W.ProbeResult(status=401),
                }
            ),
            restart=lambda: True,
        )
        self.assertEqual(state["serveo"]["verdict"], "dead")
        self.assertNotEqual(state["serveo"]["verdict"], "alive")
        self.assertGreaterEqual(state["serveo"]["consecutiveFailures"], 1)
        self.assertIn("回收", state["serveo"]["reason"])

    def test_threshold_not_reached_does_not_restart(self):
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://dead-82-110-234-120.serveousercontent.com\n"
        )
        restarts = []
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "dead-82-110-234-120.serveousercontent.com": W.ProbeResult(status=502),
                    "blksec.luckytad.vip": W.ProbeResult(status=401),
                }
            ),
            restart=lambda: restarts.append(1) or True,
        )
        self.assertEqual(restarts, [], "第一次失败不该立刻重启")
        self.assertEqual(state["serveo"]["lastDecision"], "none")

    def test_threshold_reached_triggers_restart_and_new_domain_verified(self):
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://dead-82-110-234-120.serveousercontent.com\n"
        )
        # 先把失败计数垫到阈值，模拟连续失败已发生。
        self.state_file.write_text(
            json.dumps({"serveo": {"consecutiveFailures": W.DEAD_THRESHOLD}}),
            encoding="utf-8",
        )
        restarts = []

        def restart():
            restarts.append(1)
            # 模拟 serveo 分配新域名。
            self._write_log(
                "Forwarding HTTP traffic from "
                "https://fresh-82-110-234-120.serveousercontent.com\n"
            )
            return True

        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "dead-82-110-234-120.serveousercontent.com": W.ProbeResult(status=502),
                    "fresh-82-110-234-120.serveousercontent.com": W.ProbeResult(status=401),
                    "blksec.luckytad.vip": W.ProbeResult(status=401),
                }
            ),
            restart=restart,
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertEqual(len(restarts), 1)
        self.assertEqual(state["serveo"]["verdict"], "alive")
        self.assertEqual(state["serveo"]["domain"], "fresh-82-110-234-120.serveousercontent.com")
        self.assertEqual(state["serveo"]["consecutiveFailures"], 0)
        self.assertEqual(state["serveo"]["restartsTotal"], 1)

    def test_restart_without_new_domain_is_unavailable_not_alive(self):
        """边界：重启了但没拿到新域名 —— 必须报 unavailable，不能沿用旧域名当可用。"""
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://dead-82-110-234-120.serveousercontent.com\n"
        )
        self.state_file.write_text(
            json.dumps({"serveo": {"consecutiveFailures": W.DEAD_THRESHOLD}}),
            encoding="utf-8",
        )
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "dead-82-110-234-120.serveousercontent.com": W.ProbeResult(status=502),
                    "blksec.luckytad.vip": W.ProbeResult(status=401),
                }
            ),
            restart=lambda: True,
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertEqual(state["serveo"]["verdict"], "unavailable")
        self.assertNotEqual(state["serveo"]["verdict"], "alive")

    def test_failed_restart_is_reported_not_swallowed(self):
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://dead-82-110-234-120.serveousercontent.com\n"
        )
        self.state_file.write_text(
            json.dumps({"serveo": {"consecutiveFailures": W.DEAD_THRESHOLD}}),
            encoding="utf-8",
        )
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "dead-82-110-234-120.serveousercontent.com": W.ProbeResult(status=502),
                    "blksec.luckytad.vip": W.ProbeResult(status=401),
                }
            ),
            restart=lambda: False,
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertFalse(state["serveo"]["restartSucceeded"])
        self.assertIn("失败", state["serveo"]["reason"])

    def test_no_domain_in_log_is_unavailable(self):
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map({}),
            restart=lambda: True,
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertEqual(state["serveo"]["verdict"], "unavailable")
        self.assertIsNone(state["serveo"]["domain"])

    def test_cloudflare_is_probed_but_never_restarted(self):
        """主隧道只读探测：看门狗不碰它。"""
        self._write_log(
            "Forwarding HTTP traffic from "
            "https://good-82-110-234-120.serveousercontent.com\n"
        )
        restarts = []
        state = W.run_once(
            self.paths,
            now=_ts(),
            probe=self._probe_map(
                {
                    "good-82-110-234-120.serveousercontent.com": W.ProbeResult(status=401),
                    "blksec.luckytad.vip": W.ProbeResult(status=502),
                }
            ),
            restart=lambda: restarts.append(1) or True,
        )
        self.assertEqual(state["cloudflare"]["verdict"], "dead")
        self.assertEqual(restarts, [], "看门狗只管 serveo，不该重启任何东西")


class FormatStatusTests(unittest.TestCase):
    """展示层：只有验证过的域名才能被标成「兜底地址」。"""

    def test_alive_shows_url_as_usable(self):
        state = {
            "serveo": {
                "verdict": "alive",
                "url": "https://good.serveousercontent.com",
                "domain": "good.serveousercontent.com",
                "httpStatus": 401,
                "lastProbeAt": "2026-10-24T12:00:00Z",
                "lastVerifiedAt": "2026-10-24T12:00:00Z",
                "consecutiveFailures": 0,
                "restartsTotal": 0,
                "lastRestartAt": None,
                "lastDecision": "none",
                "lastDecisionReason": "当前域名可用",
            },
            "cloudflare": {
                "verdict": "alive",
                "httpStatus": 401,
                "lastProbeAt": "2026-10-24T12:00:00Z",
            },
            "updatedAt": "2026-10-24T12:00:00Z",
        }
        text = "\n".join(W.format_status(state, now=_ts()))
        self.assertIn("https://good.serveousercontent.com", text)
        self.assertIn("alive", text)

    def test_dead_does_not_present_stale_domain_as_usable(self):
        """核心回归：失效域名不能出现在「兜底地址」那一行。"""
        state = {
            "serveo": {
                "verdict": "dead",
                "url": "https://stale.serveousercontent.com",
                "domain": "stale.serveousercontent.com",
                "httpStatus": 502,
                "reason": "HTTP 502；日志显示该转发已被 serveo 回收",
                "lastProbeAt": "2026-10-24T12:00:00Z",
                "lastVerifiedAt": None,
                "consecutiveFailures": 3,
                "restartsTotal": 1,
                "lastRestartAt": "2026-10-24T11:50:00Z",
                "lastDecision": "restart",
                "lastDecisionReason": "dead 连续 3 次，触发重建会话",
            },
            "cloudflare": {
                "verdict": "alive",
                "httpStatus": 401,
                "lastProbeAt": "2026-10-24T12:00:00Z",
            },
            "updatedAt": "2026-10-24T12:00:00Z",
        }
        text = "\n".join(W.format_status(state, now=_ts()))
        lines = text.splitlines()
        url_line = next(line for line in lines if line.startswith("兜底地址"))
        self.assertIn("不可用", url_line)
        self.assertNotIn("https://stale.serveousercontent.com", url_line)
        # 失效域名只能作为诊断信息出现。
        self.assertIn("stale.serveousercontent.com", text)
        self.assertIn("失效域名", text)

    def test_unavailable_without_domain_is_honest(self):
        state = {
            "serveo": {
                "verdict": "unavailable",
                "url": None,
                "domain": None,
                "httpStatus": None,
                "reason": "serveo 日志里没有已分配的域名",
                "lastProbeAt": "2026-10-24T12:00:00Z",
                "lastVerifiedAt": None,
                "consecutiveFailures": 1,
                "restartsTotal": 0,
                "lastRestartAt": None,
                "lastDecision": "none",
                "lastDecisionReason": "dead 计数 1/2，未达阈值",
            },
            "cloudflare": {"verdict": "alive", "httpStatus": 401, "lastProbeAt": "x"},
            "updatedAt": "2026-10-24T12:00:00Z",
        }
        text = "\n".join(W.format_status(state, now=_ts()))
        url_line = next(line for line in text.splitlines() if line.startswith("兜底地址"))
        self.assertIn("不可用", url_line)
        self.assertIn("没有已分配的域名", url_line)


class StaleConclusionTests(unittest.TestCase):
    """结论新鲜度：状态文件是缓存，不能当实时用。

    看门狗每 120 秒写一次状态。如果展示层直接读缓存里的 alive，
    就会出现「看门狗早就停了，但页面仍显示兜底地址可用」——
    这就是拿缓存冒充实时。
    """

    def test_missing_probe_time_is_stale(self):
        self.assertTrue(W.is_stale({"lastProbeAt": None}, _ts()))

    def test_old_probe_is_stale(self):
        serve = {"lastProbeAt": W._iso(_ts(minutes_ago=30))}
        self.assertTrue(W.is_stale(serve, _ts()))

    def test_recent_probe_is_not_stale(self):
        serve = {"lastProbeAt": W._iso(_ts(minutes_ago=1))}
        self.assertFalse(W.is_stale(serve, _ts()))

    def test_alive_but_stale_is_not_shown_as_usable(self):
        """核心回归：结论过期时不能展示成「兜底地址（可用）」。"""
        state = {
            "serveo": {
                "verdict": "alive",
                "url": "https://old.serveousercontent.com",
                "domain": "old.serveousercontent.com",
                "httpStatus": 401,
                "reason": "公网探测通过",
                "lastProbeAt": W._iso(_ts(minutes_ago=30)),
                "lastVerifiedAt": W._iso(_ts(minutes_ago=30)),
                "consecutiveFailures": 0,
                "restartsTotal": 0,
                "lastRestartAt": None,
                "lastDecision": "none",
                "lastDecisionReason": "当前域名可用",
            },
            "cloudflare": {"verdict": "alive", "httpStatus": 401, "lastProbeAt": "x"},
            "updatedAt": W._iso(_ts(minutes_ago=30)),
        }
        text = "\n".join(W.format_status(state, now=_ts()))
        url_line = next(line for line in text.splitlines() if line.startswith("兜底地址"))
        self.assertIn("不可用", url_line)
        self.assertIn("过期", url_line)
        self.assertNotIn("https://old.serveousercontent.com", url_line)
        self.assertIn("结论已过期", text)

    def test_alive_and_fresh_is_shown_as_usable(self):
        state = {
            "serveo": {
                "verdict": "alive",
                "url": "https://fresh.serveousercontent.com",
                "domain": "fresh.serveousercontent.com",
                "httpStatus": 401,
                "reason": "公网探测通过",
                "lastProbeAt": W._iso(_ts(minutes_ago=1)),
                "lastVerifiedAt": W._iso(_ts(minutes_ago=1)),
                "consecutiveFailures": 0,
                "restartsTotal": 0,
                "lastRestartAt": None,
                "lastDecision": "none",
                "lastDecisionReason": "当前域名可用",
            },
            "cloudflare": {"verdict": "alive", "httpStatus": 401, "lastProbeAt": "x"},
            "updatedAt": W._iso(_ts(minutes_ago=1)),
        }
        text = "\n".join(W.format_status(state, now=_ts()))
        url_line = next(line for line in text.splitlines() if line.startswith("兜底地址"))
        self.assertIn("https://fresh.serveousercontent.com", url_line)
        self.assertNotIn("不可用", url_line)


class WaitForNewDomainTests(unittest.TestCase):
    """等待新域名：旧域名不算数，超时要诚实返回 None。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.serve_log = self.tmp / "serveo.log"
        self.addCleanup(self._tmp.cleanup)

    def test_returns_new_domain(self):
        self.serve_log.write_text(
            "Forwarding HTTP traffic from https://new-82-110-234-120.serveousercontent.com\n",
            encoding="utf-8",
        )
        got = W.wait_for_new_domain(
            {"serve_log": self.serve_log},
            "old-82-110-234-120.serveousercontent.com",
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertEqual(got, "new-82-110-234-120.serveousercontent.com")

    def test_same_domain_is_not_accepted(self):
        self.serve_log.write_text(
            "Forwarding HTTP traffic from https://same-82-110-234-120.serveousercontent.com\n",
            encoding="utf-8",
        )
        got = W.wait_for_new_domain(
            {"serve_log": self.serve_log},
            "same-82-110-234-120.serveousercontent.com",
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertIsNone(got, "没换域名就算没拿到新会话")

    def test_expired_domain_is_not_accepted(self):
        """边界：日志里出现了域名但已 expired —— 不能当新域名。"""
        self.serve_log.write_text(
            "Forwarding HTTP traffic from https://new-82-110-234-120.serveousercontent.com\n"
            "Port forwarding for new-82-110-234-120.serveousercontent.com expired\n",
            encoding="utf-8",
        )
        got = W.wait_for_new_domain(
            {"serve_log": self.serve_log},
            "old-82-110-234-120.serveousercontent.com",
            sleeper=lambda _s: None,
            clock=FakeClock(),
        )
        self.assertIsNone(got)

    def test_timeout_returns_none(self):
        self.serve_log.write_text("", encoding="utf-8")
        got = W.wait_for_new_domain(
            {"serve_log": self.serve_log},
            "old.serveousercontent.com",
            sleeper=lambda _s: None,
            clock=FakeClock(step=10.0),
        )
        self.assertIsNone(got)


if __name__ == "__main__":
    unittest.main()
