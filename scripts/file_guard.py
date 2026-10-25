#!/usr/bin/env python3
"""受保护文件的写入者防护：改之前记基线，改之后确认没有别人插手。

背景：同一批核心文件在不被察觉的情况下被别的写入者改成语法损坏状态。这个脚本只负责发现
“不是我声明过的改动”，不负责判断谁改的，也不能阻止写入。

流程：
  1. snapshot --label L        记录基线（sha256 / 大小 / mtime / Python 语法状态）
  2. check --label L           改之前先跑：任何文件与上次确认的状态不一致就退出码 1
  3. （自己改文件）
  4. ack --label L --files a b 只对自己声明改过的文件登记新状态
  5. check --label L           收尾再跑一次；期间有别人写入会在这里暴露

限制：ack 之前的这段窗口里，同一个文件被别人同时写入无法区分；check 能抓到的是
“声明之外的文件变了”、“两次确认之间文件变了”、“文件被删或出现新的匹配”、“Python 文件语法损坏”。

受保护清单在 config/protected-files.json，状态文件在 work/file-guard/<label>.json。
退出码：0 正常；1 发现异常；2 用法或配置错误。
"""
from __future__ import annotations

import argparse
import ast
import glob
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_REL = "config/protected-files.json"
STATE_DIR_REL = "work/file-guard"
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
GLOB_CHARS = set("*?[")
STATE_VERSION = 1

# check 里这些状态表示异常，其余只是提示。
FAILING = {"drift", "deleted", "new_match", "pattern_unmatched", "syntax_error", "unstable"}


class GuardError(Exception):
    """用法或配置错误（退出码 2）。code 是稳定的英文标识。"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_label(label: str) -> str:
    if not isinstance(label, str) or not LABEL_RE.match(label):
        raise GuardError(f"label_invalid:{label!r}")
    return label


def validate_pattern(pattern: str) -> str:
    if not isinstance(pattern, str) or not pattern.strip():
        raise GuardError("pattern_empty")
    if "\\" in pattern or pattern.startswith("/") or re.match(r"^[A-Za-z]:", pattern):
        raise GuardError(f"pattern_not_relative:{pattern}")
    if ".." in Path(pattern).parts:
        raise GuardError(f"pattern_parent_reference:{pattern}")
    return pattern


def load_patterns(root: Path, config_path: Path | None = None) -> list[str]:
    path = config_path or (root / CONFIG_REL)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise GuardError(f"config_missing:{path}")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GuardError(f"config_invalid:{error}")
    if not isinstance(data, dict) or data.get("version") != 1:
        raise GuardError("config_version_unsupported")
    items = data.get("protected")
    if not isinstance(items, list) or not items or not all(isinstance(item, str) for item in items):
        raise GuardError("config_protected_invalid")
    patterns: list[str] = []
    for item in items:
        validate_pattern(item)
        if item not in patterns:
            patterns.append(item)
    return patterns


def expand(root: Path, patterns: list[str]) -> tuple[dict[str, str], list[str]]:
    """返回 ({相对路径: 来源模式}, 没有任何匹配的模式)。符号链接指到仓库外直接报错。"""
    real_root = Path(os.path.realpath(root))
    files: dict[str, str] = {}
    unmatched: list[str] = []
    for pattern in patterns:
        if GLOB_CHARS & set(pattern):
            hits = sorted(glob.glob(str(root / pattern), recursive=True))
        else:
            hits = [str(root / pattern)] if os.path.lexists(root / pattern) else []
        hits = [hit for hit in hits if os.path.isfile(hit)]
        if not hits:
            unmatched.append(pattern)
            continue
        for hit in hits:
            try:
                Path(os.path.realpath(hit)).relative_to(real_root)
            except ValueError:
                raise GuardError(f"path_escapes_root:{hit}")
            rel = Path(hit).relative_to(root).as_posix()
            files.setdefault(rel, pattern)
    return files, unmatched


def _python_syntax(data: bytes) -> str:
    try:
        ast.parse(data.decode("utf-8"))
        return "ok"
    except UnicodeDecodeError:
        return "error:not_utf8"
    except (SyntaxError, ValueError) as error:
        line = getattr(error, "lineno", None)
        message = getattr(error, "msg", str(error))
        return f"error:line {line}: {message}" if line else f"error:{message}"


def fingerprint(path: Path, attempts: int = 3) -> dict:
    """读文件并取指纹。读的过程中文件被写入就重试，仍不稳定则报 unstable。"""
    for _ in range(attempts):
        with open(path, "rb") as handle:
            before = os.fstat(handle.fileno())
            data = handle.read()
            after = os.fstat(handle.fileno())
        if (before.st_mtime_ns, before.st_size) == (after.st_mtime_ns, after.st_size) and len(data) == after.st_size:
            return {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mtimeNs": after.st_mtime_ns,
                "syntax": _python_syntax(data) if path.suffix == ".py" else None,
            }
    raise GuardError(f"file_unstable:{path}")


def _state_path(root: Path, label: str) -> Path:
    return root / STATE_DIR_REL / f"{validate_label(label)}.json"


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=".tmp-", suffix=".json", delete=False)
    try:
        with handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def _read_state(root: Path, label: str) -> dict:
    path = _state_path(root, label)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise GuardError(f"snapshot_missing:{label}")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GuardError(f"snapshot_corrupt:{error}")
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION or not isinstance(state.get("files"), dict):
        raise GuardError("snapshot_corrupt:shape")
    return state


def snapshot(root: Path, label: str, config_path: Path | None = None) -> dict:
    path = _state_path(root, label)
    if path.exists():
        raise GuardError(f"snapshot_exists:{label}")  # 不覆盖旧基线，换一个 label
    patterns = load_patterns(root, config_path)
    files, unmatched = expand(root, patterns)
    if unmatched:
        raise GuardError("pattern_unmatched:" + ",".join(unmatched))  # 防止写错路径后悄悄什么都没保护
    entries = {}
    for rel in sorted(files):
        finger = fingerprint(root / rel)
        entries[rel] = {"pattern": files[rel], "baseline": finger, "acked": finger}
    state = {"version": STATE_VERSION, "label": label, "createdAt": _now(), "root": str(root), "patterns": patterns,
             "files": entries, "history": [{"at": _now(), "event": "snapshot", "files": sorted(entries)}]}
    _write_state(path, state)
    return state


def check(root: Path, label: str) -> dict:
    """只读。把每个受保护文件和上次确认的状态比较。"""
    state = _read_state(root, label)
    files, unmatched = expand(root, state["patterns"])
    rows = []
    for rel, entry in sorted(state["files"].items()):
        target = root / rel
        row = {"path": rel, "status": "ok", "detail": "", "changedFromBaseline": False, "syntax": None}
        if not os.path.isfile(target):
            row.update(status="deleted", detail="文件不存在了")
            rows.append(row)
            continue
        try:
            now = fingerprint(target)
        except GuardError as error:
            row.update(status="unstable", detail=str(error))
            rows.append(row)
            continue
        acked, base = entry["acked"], entry["baseline"]
        row["syntax"] = now["syntax"]
        row["changedFromBaseline"] = now["sha256"] != base["sha256"]
        if now["sha256"] != acked["sha256"]:
            row.update(status="drift", detail=f"内容与上次确认不同（{acked['sha256'][:8]} → {now['sha256'][:8]}），不是 ack 过的改动")
        elif now["syntax"] and now["syntax"].startswith("error"):
            row.update(status="syntax_error", detail=now["syntax"])
        elif now["mtimeNs"] != acked["mtimeNs"]:
            row.update(status="touched", detail="内容没变但修改时间变了，可能被重写过（仅提示）")
        if row["status"] == "drift" and now["syntax"] and now["syntax"].startswith("error"):
            row["detail"] += f"；且语法损坏：{now['syntax']}"
        rows.append(row)
    for rel in sorted(set(files) - set(state["files"])):
        rows.append({"path": rel, "status": "new_match", "detail": f"出现了快照之后新匹配的文件（模式 {files[rel]}）", "changedFromBaseline": True, "syntax": None})
    for pattern in unmatched:
        if not (GLOB_CHARS & set(pattern)):
            continue  # 具体路径没匹配到就是该文件被删，上面的 deleted 行已经报告，不重复
        rows.append({"path": pattern, "status": "pattern_unmatched", "detail": "模式现在没有匹配到任何文件", "changedFromBaseline": True, "syntax": None})
    failing = [row for row in rows if row["status"] in FAILING]
    return {"label": label, "checkedAt": _now(), "ok": not failing, "rows": rows}


def ack(root: Path, label: str, declared: list[str], allow_syntax_error: bool = False) -> dict:
    """登记自己改过的文件。只允许登记快照里已有的文件，未声明的文件保持原状态继续被监视。"""
    if not declared:
        raise GuardError("ack_requires_files")
    state = _read_state(root, label)
    normalized = []
    for item in declared:
        rel = Path(validate_pattern(item)).as_posix()
        if rel not in state["files"]:
            raise GuardError(f"ack_not_tracked:{rel}")
        normalized.append(rel)
    updates = {}
    for rel in normalized:
        target = root / rel
        if not os.path.isfile(target):
            raise GuardError(f"ack_file_missing:{rel}")
        updates[rel] = fingerprint(target)
    broken = {rel: finger["syntax"] for rel, finger in updates.items() if finger["syntax"] and finger["syntax"].startswith("error")}
    if broken and not allow_syntax_error:
        raise GuardError("ack_syntax_error:" + "; ".join(f"{rel}={why}" for rel, why in broken.items()))
    history_rows = []
    for rel, finger in updates.items():
        entry = state["files"][rel]
        history_rows.append({"path": rel, "from": entry["acked"]["sha256"], "to": finger["sha256"]})
        entry["acked"] = finger
    state["history"].append({"at": _now(), "event": "ack", "files": history_rows})
    _write_state(_state_path(root, label), state)
    return {"label": label, "acked": history_rows}


def _format_check(report: dict) -> str:
    glyph = {"ok": "✔", "touched": "·", "drift": "✘", "deleted": "✘", "new_match": "✘", "pattern_unmatched": "✘", "syntax_error": "✘", "unstable": "✘"}
    lines = [f"受保护文件检查 label={report['label']} 时间={report['checkedAt']}"]
    for row in report["rows"]:
        note = f"  {row['detail']}" if row["detail"] else ""
        mark = "（相对基线已改）" if row["changedFromBaseline"] and row["status"] == "ok" else ""
        syntax = f" [语法 {row['syntax']}]" if row["syntax"] else ""
        lines.append(f"  {glyph.get(row['status'], '?')} {row['status']:<17} {row['path']}{syntax}{mark}{note}")
    lines.append("结论：" + ("无异常" if report["ok"] else "发现异常，先停手确认再继续编辑"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=str(ROOT), help="仓库根目录（测试用）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("snapshot", "check", "ack"):
        item = sub.add_parser(name)
        item.add_argument("--label", required=True)
        if name == "snapshot":
            item.add_argument("--config", default=None)
        if name == "ack":
            item.add_argument("--files", nargs="+", required=True)
            item.add_argument("--allow-syntax-error", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    try:
        if args.command == "snapshot":
            state = snapshot(root, args.label, Path(args.config) if args.config else None)
            out = {"label": args.label, "files": {rel: entry["baseline"]["sha256"] for rel, entry in state["files"].items()}}
            print(json.dumps(out, ensure_ascii=False, indent=2) if args.json else
                  f"已记录基线 label={args.label}\n" + "\n".join(f"  {rel}  sha256={entry['baseline']['sha256'][:12]}  语法={entry['baseline']['syntax']}" for rel, entry in state["files"].items()))
            return 0
        if args.command == "ack":
            result = ack(root, args.label, args.files, args.allow_syntax_error)
            print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else
                  "已登记：\n" + "\n".join(f"  {row['path']}  {row['from'][:8]} → {row['to'][:8]}" for row in result["acked"]))
            return 0
        report = check(root, args.label)
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else _format_check(report))
        return 0 if report["ok"] else 1
    except GuardError as error:
        print(f"file_guard 错误：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
