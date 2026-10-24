#!/usr/bin/env python3
"""serveo 兜底隧道看门狗：探测存活、静默失效时重建会话、记录可核验状态。

背景（本机实测，见 deploy/tunnel/status.sh 与 ~/Library/Logs/SecurityWebTunnel/serveo.log）：
  serveo.net 的免费 SSH 反向转发会被服务端单方面回收，日志长这样：

      Forwarding HTTP traffic from https://<随机子域>-82-110-234-120.serveousercontent.com
      Port forwarding for <随机子域>-... expired
      Connection to serveo.net closed by remote host.

  关键点：回收之后 **ssh 进程仍然活着**（serveo 不主动断开 SSH 会话），
  所以 launchd 的 KeepAlive 不会重启它，那个随机域名也还留在日志里。
  于是现场是「进程在 / 域名在 / 转发已死」：公网访问返回 502，
  进程级没有任何错误信号，只能靠人翻日志才发现。

  旧 status.sh 用 `grep -oE 'https://[a-z0-9.-]+serveousercontent.com' | tail -1`
  取域名，会把一个已经过期的域名当成「兜底地址」展示 —— 状态合法，语义错误。

本脚本做四件事：
  1) 解析 serveo 日志，区分「日志里分配过域名」与「该域名当前是否仍然有效」
  2) 主动探测公网链路是否真的通到本机代理（8789）。无认证探测即可：
     代理对缺口令的请求返回 401，这本身证明隧道已把流量送到本机，
     比「看进程/看日志」更接近真实可用性。
  3) 连续失败达到阈值才重建会话，并受冷却时间与每小时重启次数上限约束，
     避免网络抖动时反复重启把兜底也搞挂。
  4) 把「已验证存活」的域名写进状态文件供 status.sh 展示；
     未验证的域名只作为诊断信息出现，绝不当成可用地址。

只读探测 + 只重启 serveo 自己的 launchd job，不碰 Cloudflare 主隧道
（主隧道由 deploy/tunnel/cloudflared/run.sh 自己看门狗），
不碰 Web 服务与采集任务。

用法：
    python3 scripts/tunnel_serveo_watchdog.py once      # 跑一轮（launchd 用这个）
    python3 scripts/tunnel_serveo_watchdog.py status    # 打印当前状态
    python3 scripts/tunnel_serveo_watchdog.py install   # 部署并注册 launchd 任务
    python3 scripts/tunnel_serveo_watchdog.py uninstall # 注销并删除部署副本
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

APP_SUPPORT = Path.home() / "Library" / "Application Support" / "SecurityWebTunnel"
LOG_DIR = Path.home() / "Library" / "Logs" / "SecurityWebTunnel"
SERVE_LOG = LOG_DIR / "serveo.log"
WATCHDOG_LOG = LOG_DIR / "serveo-watchdog.log"
STATE_FILE = APP_SUPPORT / "serveo-state.json"
DEPLOYED_SCRIPT = APP_SUPPORT / "serveo-watchdog.py"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / "com.d288.security.webtunnel.serveo-watchdog.plist"

SERVE_LABEL = "com.d288.security.webtunnel.serveo"
WATCHDOG_LABEL = "com.d288.security.webtunnel.serveo-watchdog"
CF_URL = "https://blksec.luckytad.vip"
HEALTH_PATH = "/api/health"

# 判定阈值：连续失败几次才动手，避免把瞬时抖动升级成重启风暴。
DEAD_THRESHOLD = 2        # 明确的死信号（502/503/504/连不上）
UNKNOWN_THRESHOLD = 3     # 不确定信号（5xx 之外的意外状态码）
RESTART_COOLDOWN_SECONDS = 180
RESTART_HOURLY_CAP = 6
PROBE_TIMEOUT_SECONDS = 12
NEW_DOMAIN_WAIT_SECONDS = 45
# 看门狗每 120 秒跑一轮；超过这个时间还没更新过的结论算「过期结论」，
# 展示时必须标成 stale，不能当成当前可用（缓存冒充实时是静默错值）。
STALE_AFTER_SECONDS = 300

# 域名形态：serveo 免费隧道分配的是 <hash>-<公网IP>.serveousercontent.com
_HOST = r"[a-z0-9][a-z0-9.-]*serveousercontent\.com"
_FORWARD_RE = re.compile(r"Forwarding HTTP traffic from (https://" + _HOST + r")")
_EXPIRED_RE = re.compile(r"Port forwarding for (" + _HOST + r") expired")
_CLOSED_RE = re.compile(r"Connection to serveo\.net closed by remote host")
_URL_RE = re.compile(r"https://" + _HOST)

# 明确「隧道还活着」的状态码。
#   200：带口令时 /api/health 的正常响应
#   401：本机代理对缺口令请求的响应 —— 证明流量确实送到了本机代理
#   403：应用侧 Host 校验拒绝 —— 隧道是通的，拒的是请求本身
ALIVE_CODES = frozenset({200, 401, 403})
# 明确「转发已死」的状态码：serveo 自己无法连到本地转发时就回这个。
DEAD_CODES = frozenset({502, 503, 504})


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(text: str) -> Optional[datetime]:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class LogState:
    """从 serveo 日志解析出来的会话状态。

    domain     —— 日志里最后一次分配的域名（可能已经过期）
    alive      —— 该域名当前是否仍被 serveo 认定有效
    expired    —— 明确看到过该域名的 expired / closed 记录
    forwards   —— 日志里出现过的 Forwarding 行数（会话代数）
    """

    domain: Optional[str] = None
    alive: bool = False
    expired: bool = False
    forwards: int = 0

    @property
    def url(self) -> Optional[str]:
        return f"https://{self.domain}" if self.domain else None


def parse_serveo_log(text: str) -> LogState:
    """按日志顺序解析 serveo 会话状态。

    顺序很关键：serveo 的日志顺序是
        Forwarding A -> expired A -> closed -> Forwarding B
    所以「expired 只作废它自己那个域名」「closed 作废当前域名」，
    随后的 Forwarding 会重新把 alive 置回 True。

    边界：日志为空 / 只有噪声行时不编造域名，返回 domain=None。
    """
    state = LogState()
    for line in (text or "").splitlines():
        match = _FORWARD_RE.search(line)
        if match:
            state.domain = _URL_RE.search(match.group(1)).group(0).split("://", 1)[1]
            state.alive = True
            state.expired = False
            state.forwards += 1
            continue
        match = _EXPIRED_RE.search(line)
        if match:
            # expired 只作废它自己指向的域名，别误伤当前域名。
            if state.domain and match.group(1) == state.domain:
                state.alive = False
                state.expired = True
            continue
        if _CLOSED_RE.search(line):
            # 连接被远端关闭，当前域名作废（除非后面又有新的 Forwarding）。
            state.alive = False
            state.expired = True
    return state


@dataclass
class ProbeResult:
    status: Optional[int] = None
    error: Optional[str] = None
    latency_ms: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error is None


def classify_probe(result: ProbeResult) -> str:
    """把一次探测归到 alive / dead / unknown 三档。

    拿不准的必须说 unknown，不能往 alive 靠 —— 「看起来成功但语义错误」
    比「明确报告不确定」危险得多。
    """
    if result.error:
        # 连不上：DNS 失败 / TCP 超时 / TLS 失败，都属于「转发没在服务」。
        return "dead"
    if result.status is None:
        return "unknown"
    if result.status in ALIVE_CODES:
        return "alive"
    if result.status in DEAD_CODES:
        return "dead"
    return "unknown"


def default_probe(url: str, timeout: int = PROBE_TIMEOUT_SECONDS) -> ProbeResult:
    """无认证探测公网地址。

    刻意不带口令：401 同样能证明隧道把流量送到了本机代理。
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        url + HEALTH_PATH, method="GET", headers={"User-Agent": "serveo-watchdog/1.0"}
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(2048)
            elapsed = int((time.monotonic() - started) * 1000)
            return ProbeResult(status=response.status, error=None, latency_ms=elapsed)
    except urllib.error.HTTPError as error:
        elapsed = int((time.monotonic() - started) * 1000)
        return ProbeResult(status=error.code, error=None, latency_ms=elapsed)
    except Exception as error:  # URLError / socket timeout / SSL 等
        elapsed = int((time.monotonic() - started) * 1000)
        return ProbeResult(status=None, error=f"{type(error).__name__}: {error}", latency_ms=elapsed)


def default_restart() -> bool:
    """重启 serveo 的 launchd job，让它重新分配一个域名。"""
    domain = f"gui/{os.getuid()}"
    try:
        subprocess.run(
            ["launchctl", "kickstart", "-k", f"{domain}/{SERVE_LABEL}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return True
    except (subprocess.SubprocessError, OSError) as error:
        print(f"[serveo-watchdog] 重启 {SERVE_LABEL} 失败: {error}", file=sys.stderr)
        return False


@dataclass
class Decision:
    action: str          # 'none' | 'restart'
    reason: str
    threshold: Optional[int] = None


def decide_action(
    serve: Dict,
    log_state: LogState,
    now: datetime,
    dead_threshold: int = DEAD_THRESHOLD,
    unknown_threshold: int = UNKNOWN_THRESHOLD,
    cooldown: int = RESTART_COOLDOWN_SECONDS,
    hourly_cap: int = RESTART_HOURLY_CAP,
) -> Decision:
    """根据状态决定要不要重建 serveo 会话。

    顺序很重要：先看冷却期和频率上限，再看失败计数，
    否则会在网络长时间不可用时把重启次数用光。
    """
    verdict = serve.get("verdict")
    if verdict == "alive":
        return Decision("none", "当前域名可用")

    failures = int(serve.get("consecutiveFailures") or 0)

    last_restart = _parse_iso(serve.get("lastRestartAt") or "")
    if last_restart is not None:
        elapsed = (now - last_restart).total_seconds()
        if 0 <= elapsed < cooldown:
            return Decision("none", f"冷却中，距上次重启 {int(elapsed)}s / {cooldown}s")

    history = [
        stamp
        for stamp in (_parse_iso(item) for item in serve.get("restartHistory") or [])
        if stamp is not None and (now - stamp) < timedelta(hours=1)
    ]
    if len(history) >= hourly_cap:
        return Decision("none", f"已达每小时重启上限 {hourly_cap}")

    if not log_state.domain:
        # 压根没分配到域名：serveo job 可能没起来。
        return Decision("restart", "serveo 尚未分配域名", threshold=1)

    threshold = dead_threshold if verdict == "dead" else unknown_threshold
    if failures < threshold:
        return Decision(
            "none",
            f"{verdict} 计数 {failures}/{threshold}，未达阈值",
            threshold=threshold,
        )
    return Decision("restart", f"{verdict} 连续 {failures} 次，触发重建会话", threshold=threshold)


def load_state(path: Path) -> Dict:
    """读取状态文件；损坏或缺失都退回初始状态，不崩、不编造。"""
    blank = {
        "schemaVersion": 1,
        "serveo": {
            "url": None,
            "domain": None,
            "verdict": "unavailable",
            "httpStatus": None,
            "reason": "尚未探测",
            "lastProbeAt": None,
            "lastVerifiedAt": None,
            "lastRestartAt": None,
            "consecutiveFailures": 0,
            "restartsTotal": 0,
            "restartHistory": [],
            # run_once 每次都会写这几个键，模板里必须齐全，
            # 否则新建状态文件会缺字段（读回来是 None，语义却是"没有决策"）。
            "logSessionAlive": False,
            "logSessionExpired": False,
            "sessionForwards": 0,
            "lastDecision": "none",
            "lastDecisionReason": "尚未决策",
            "restartSucceeded": None,
        },
        "cloudflare": {
            "url": CF_URL,
            "verdict": "unknown",
            "httpStatus": None,
            "lastProbeAt": None,
            "reason": "尚未探测",
        },
    }
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return copy.deepcopy(blank)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return copy.deepcopy(blank)
    if not isinstance(data, dict):
        return copy.deepcopy(blank)
    for key, defaults in blank.items():
        if not isinstance(data.get(key), dict):
            data[key] = copy.deepcopy(defaults)
    for key, defaults in blank["serveo"].items():
        data["serveo"].setdefault(key, copy.deepcopy(defaults))
    for key, defaults in blank["cloudflare"].items():
        data["cloudflare"].setdefault(key, copy.deepcopy(defaults))
    return data


def save_state(path: Path, state: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def wait_for_new_domain(
    paths: Dict[str, Path],
    old_domain: Optional[str],
    sleeper: Callable[[float], None] = time.sleep,
    timeout: int = NEW_DOMAIN_WAIT_SECONDS,
    poll: float = 2.0,
    clock: Callable[[], float] = time.monotonic,
) -> Optional[str]:
    """等 serveo 分配出新的域名。

    旧域名不算数：重启前后的域名可能是同一个（极端情况），
    但更常见的是新域名；返回 None 表示超时没等到。

    clock 可注入，便于测试里用假时钟推进，避免真等 45 秒。
    """
    deadline = clock() + timeout
    while clock() < deadline:
        try:
            text = paths["serve_log"].read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        state = parse_serveo_log(text)
        if state.domain and state.domain != old_domain and state.alive:
            return state.domain
        sleeper(poll)
    return None


def run_once(
    paths: Optional[Dict[str, Path]] = None,
    *,
    now: Optional[datetime] = None,
    probe: Optional[Callable[[str], ProbeResult]] = None,
    restart: Optional[Callable[[], bool]] = None,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Dict:
    """跑一轮看门狗，返回写盘后的状态。

    所有外部依赖（探测、重启、等待）都可注入，测试里不需要真网络。
    """
    paths = paths or {"serve_log": SERVE_LOG, "state_file": STATE_FILE}
    now = now or _now_utc()
    probe_fn = probe or default_probe
    restart_fn = restart or default_restart

    state = load_state(paths["state_file"])
    serve = state["serveo"]

    try:
        log_text = paths["serve_log"].read_text(encoding="utf-8", errors="replace")
    except OSError:
        log_text = ""
    log_state = parse_serveo_log(log_text)

    serve["domain"] = log_state.domain
    serve["url"] = log_state.url
    serve["logSessionAlive"] = log_state.alive
    serve["logSessionExpired"] = log_state.expired
    serve["sessionForwards"] = log_state.forwards

    if log_state.domain:
        result = probe_fn(log_state.url)
        verdict = classify_probe(result)
        serve["httpStatus"] = result.status
        serve["lastProbeAt"] = _iso(now)
        serve["verdict"] = verdict
        if verdict == "alive":
            serve["consecutiveFailures"] = 0
            serve["lastVerifiedAt"] = _iso(now)
            serve["reason"] = "公网探测通过"
        else:
            serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1
            serve["reason"] = result.error or f"HTTP {result.status}"
            if not log_state.alive:
                serve["reason"] += "；日志显示该转发已被 serveo 回收"
    else:
        serve["verdict"] = "unavailable"
        serve["httpStatus"] = None
        serve["lastProbeAt"] = _iso(now)
        serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1
        serve["reason"] = "serveo 日志里没有已分配的域名"

    decision = decide_action(serve, log_state, now)
    serve["lastDecision"] = decision.action
    serve["lastDecisionReason"] = decision.reason

    if decision.action == "restart":
        serve["lastRestartAt"] = _iso(now)
        serve["restartsTotal"] = int(serve.get("restartsTotal") or 0) + 1
        history = list(serve.get("restartHistory") or [])
        history.append(_iso(now))
        serve["restartHistory"] = history[-50:]

        ok = restart_fn()
        serve["restartSucceeded"] = bool(ok)
        if ok:
            new_domain = wait_for_new_domain(
                paths, log_state.domain, sleeper=sleeper, clock=clock
            )
            if new_domain:
                serve["domain"] = new_domain
                serve["url"] = f"https://{new_domain}"
                follow_up = probe_fn(serve["url"])
                follow_verdict = classify_probe(follow_up)
                serve["httpStatus"] = follow_up.status
                serve["verdict"] = follow_verdict
                if follow_verdict == "alive":
                    serve["consecutiveFailures"] = 0
                    serve["lastVerifiedAt"] = _iso(now)
                    serve["reason"] = "重建会话后验证通过"
                else:
                    serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1
                    serve["reason"] = follow_up.error or f"重建后 HTTP {follow_up.status}"
            else:
                serve["verdict"] = "unavailable"
                serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1
                serve["reason"] = "重建会话后未拿到新域名"
        else:
            serve["consecutiveFailures"] = int(serve.get("consecutiveFailures") or 0) + 1
            serve["reason"] = "重建会话失败（launchctl kickstart 未成功）"

    # 主隧道只做只读探测：它由 deploy/tunnel/cloudflared/run.sh 自己看门狗，
    # 这里不重启，只把「通不通」如实记下来。
    cf = state["cloudflare"]
    cf_result = probe_fn(CF_URL)
    cf["httpStatus"] = cf_result.status
    cf["verdict"] = classify_probe(cf_result)
    cf["lastProbeAt"] = _iso(now)
    cf["reason"] = cf_result.error or f"HTTP {cf_result.status}"

    state["updatedAt"] = _iso(now)
    save_state(paths["state_file"], state)
    return state


def is_stale(serve: Dict, now: datetime, max_age: int = STALE_AFTER_SECONDS) -> bool:
    """判断状态里的结论是否已经过期。

    状态文件是看门狗写下的缓存结论，不是实时探测结果。
    超过 max_age 没更新过就不能当成「当前可用」——
    否则就是把缓存描述成实时。
    """
    stamp = _parse_iso(serve.get("lastProbeAt") or "")
    if stamp is None:
        return True
    age = (now - stamp).total_seconds()
    return age > max_age


def format_status(state: Dict, now: Optional[datetime] = None) -> List[str]:
    """把状态渲染成人能读的几行。

    关键：只有在 verdict == 'alive' **且结论未过期** 时，才把地址标成「兜底地址（可用）」；
    其余情况显式标注状态，绝不把没验证过的域名说成可用。
    """
    now = now or _now_utc()
    serve = state.get("serveo") or {}
    cloudflare = state.get("cloudflare") or {}
    verdict = serve.get("verdict")
    stale = is_stale(serve, now)

    lines: List[str] = []
    lines.append(f"serveo 状态   : {verdict}{'（结论已过期）' if stale else ''}")
    if verdict == "alive" and not stale:
        lines.append(f"兜底地址      : {serve.get('url')}")
        lines.append(f"  最近验证    : {serve.get('lastVerifiedAt')}")
    else:
        if verdict == "alive":
            reason = f"上次结论已过期（{serve.get('lastProbeAt')}），未重新验证"
        else:
            reason = serve.get("reason") or "未知原因"
        lines.append(f"兜底地址      : <不可用>（{reason}）")
        if serve.get("url"):
            lines.append(f"  失效域名    : {serve.get('url')}")
    lines.append(f"  最近探测    : {serve.get('lastProbeAt')}  HTTP {serve.get('httpStatus')}")
    lines.append(f"  连续失败    : {serve.get('consecutiveFailures')}")
    lines.append(f"  累计重启    : {serve.get('restartsTotal')}（上次 {serve.get('lastRestartAt')}）")
    lines.append(f"  最近决策    : {serve.get('lastDecision')} — {serve.get('lastDecisionReason')}")

    lines.append(f"主隧道状态    : {cloudflare.get('verdict')}  HTTP {cloudflare.get('httpStatus')}")
    lines.append(f"  最近探测    : {cloudflare.get('lastProbeAt')}")
    lines.append(f"状态更新时间  : {state.get('updatedAt')}")
    return lines


def _copy_without_xattr(src: Path, dst: Path) -> None:
    """用 cp -X 复制，剥掉 com.apple.macl 标记。

    launchd 拉起的进程不能读带该标记的文件（会 EPERM），
    所以部署副本必须不带 xattr。
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["/bin/cp", "-X", str(src), str(dst)], check=True)
    dst.chmod(0o755)


def _plist_content() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>EnvironmentVariables</key>
\t<dict>
\t\t<key>NO_PROXY</key>
\t\t<string>127.0.0.1,localhost,::1</string>
\t\t<key>no_proxy</key>
\t\t<string>127.0.0.1,localhost,::1</string>
\t\t<key>PATH</key>
\t\t<string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
\t</dict>
\t<key>Label</key>
\t<string>{WATCHDOG_LABEL}</string>
\t<key>ProgramArguments</key>
\t<array>
\t\t<string>/usr/bin/python3</string>
\t\t<string>{DEPLOYED_SCRIPT}</string>
\t\t<string>once</string>
\t</array>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>StartInterval</key>
\t<integer>120</integer>
\t<key>ProcessType</key>
\t<string>Background</string>
\t<key>StandardErrorPath</key>
\t<string>{WATCHDOG_LOG}</string>
\t<key>StandardOutPath</key>
\t<string>{WATCHDOG_LOG}</string>
\t<key>ThrottleInterval</key>
\t<integer>30</integer>
\t<key>WorkingDirectory</key>
\t<string>/</string>
</dict>
</plist>
"""


def _launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["launchctl", *args], capture_output=True, text=True, check=False, timeout=30
    )


def install() -> int:
    source = Path(__file__).resolve()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _copy_without_xattr(source, DEPLOYED_SCRIPT)
    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    PLIST_PATH.write_text(_plist_content(), encoding="utf-8")
    os.chmod(PLIST_PATH, 0o644)

    domain = f"gui/{os.getuid()}"
    # 已加载过先 bootout，避免 bootstrap 报「已存在」。
    _launchctl("bootout", f"{domain}/{WATCHDOG_LABEL}")
    result = _launchctl("bootstrap", domain, str(PLIST_PATH))
    if result.returncode != 0:
        print(f"[serveo-watchdog] bootstrap 失败: {result.stderr.strip()}", file=sys.stderr)
        return 1
    _launchctl("kickstart", f"{domain}/{WATCHDOG_LABEL}")
    print(f"[serveo-watchdog] 已部署并启动：{PLIST_PATH}")
    print(f"[serveo-watchdog] 部署副本：{DEPLOYED_SCRIPT}")
    return 0


def uninstall() -> int:
    domain = f"gui/{os.getuid()}"
    _launchctl("bootout", f"{domain}/{WATCHDOG_LABEL}")
    for path in (PLIST_PATH, DEPLOYED_SCRIPT):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    print("[serveo-watchdog] 已注销并清理部署文件")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="serveo 兜底隧道看门狗")
    parser.add_argument("command", choices=["once", "status", "json", "install", "uninstall"])
    args = parser.parse_args(argv)

    if args.command == "once":
        state = run_once()
        serve = state["serveo"]
        print(
            f"[serveo-watchdog] {serve.get('verdict')} "
            f"domain={serve.get('domain')} http={serve.get('httpStatus')} "
            f"action={serve.get('lastDecision')}"
        )
        return 0

    if args.command == "status":
        print("\n".join(format_status(load_state(STATE_FILE))))
        return 0

    if args.command == "json":
        # 机器可读输出：给 status.sh 这类脚本用，
        # 不要去解析人类可读文本里的固定措辞。
        state = load_state(STATE_FILE)
        serve = state.get("serveo") or {}
        usable = serve.get("verdict") == "alive" and not is_stale(serve, _now_utc())
        print(
            json.dumps(
                {
                    "url": serve.get("url") if usable else None,
                    "verdict": serve.get("verdict"),
                    "stale": is_stale(serve, _now_utc()),
                    "usable": usable,
                    "domain": serve.get("domain"),
                    "httpStatus": serve.get("httpStatus"),
                    "reason": serve.get("reason"),
                    "lastProbeAt": serve.get("lastProbeAt"),
                    "lastVerifiedAt": serve.get("lastVerifiedAt"),
                    "consecutiveFailures": serve.get("consecutiveFailures"),
                    "restartsTotal": serve.get("restartsTotal"),
                    "lastDecision": serve.get("lastDecision"),
                    "lastDecisionReason": serve.get("lastDecisionReason"),
                    "cloudflare": state.get("cloudflare"),
                    "updatedAt": state.get("updatedAt"),
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "install":
        return install()

    return uninstall()


if __name__ == "__main__":
    raise SystemExit(main())
