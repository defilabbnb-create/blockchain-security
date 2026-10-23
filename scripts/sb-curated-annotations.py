#!/usr/bin/env python3
"""从 SmartBugs SB Curated 的内联标注生成可对标的评测口径。

SB Curated 的每个样本在源码里带 `// <yes> <report> REENTRANCY` 这样的行内标注。
本脚本只做一件事：把这些标注读出来，和本项目 `ground-truth.json` 里人工写的
`knownIssues` 对照，并报告两者的差异。

为什么不直接改 `knownIssues`
---------------------------
标注与源码不一致时（例如某样本的标注指向一个本项目并未采纳的性质），改
`knownIssues` 就等于把评测基准改成"总是和检测器一致"，precision 随即失去意义。
本脚本因此只报告差异：哪一条标注没有进入 `knownIssues`、哪一条 `knownIssues`
没有对应标注、两者拼写是否一致。裁定权留给人工。

映射表是显式的
--------------
SB Curated 用 `UNCHECKED_LL_CALLS` 这种大写下划线拼写，本项目用
`unchecked_low_level_calls`。映射写在 `SB_CURATED_CLASS_MAP` 里而不是靠
字符串猜测：拼写相近不等于同一类别，而漏映射的类别会被报告成"缺失"而不是
被静默合并。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "benchmark" / "contracts"

# `// <yes> <report> REENTRANCY` / `/* <yes> <report> UNCHECKED_LL_CALLS */`
#
# The annotation is terminated by end of line, an arrow (`-->`), or the closing
# `*/` of a block comment.  Requiring only `$` after the class name missed every
# block-comment form, which is how `unchecked_return_value.sol` and the other
# `/* ... */` samples ended up looking unannotated.
ANNOTATION_RE = re.compile(
    r'<yes>\s*<report>\s*(?P<classes>[A-Za-z0-9_,\s]+?)'
    r'(?=\s*(?:-->|$|\*/))',
    re.M)

# SB Curated 的类别名 -> 本项目角色名。只列确认对应的，未列出的会被报告为未知。
SB_CURATED_CLASS_MAP = {
    'ACCESS_CONTROL': 'access_control',
    'ARITHMETIC': 'arithmetic',
    'BAD_RANDOMNESS': 'bad_randomness',
    'DENIAL_OF_SERVICE': 'denial_of_service',
    'FRONT_RUNNING': 'front_running',
    'RACE_CONDITION': 'race_condition',
    'REENTRANCY': 'reentrancy',
    'SHORT_ADDRESSES': 'short_addresses',
    'TIME_MANIPULATION': 'time_manipulation',
    'UNCHECKED_LL_CALLS': 'unchecked_low_level_call',
    'INCORRECT_INTERFACE': 'incorrect_interface',
    'HONEYPOTS': 'honeypots',
    'VARIABLE_SHADOWING': 'variable_shadowing',
}


def strip_annotation_comment(text: str) -> str:
    """返回把标注注释替换成等长空白后的源码。

    等长替换保持所有字节偏移不变，这样按 offset 定位的检测器看到的仍是同一
    份源码。标注本身绝不能成为证据：它是人工写的答案，不是被测代码的性质。

    按 `match.start()` 直接写入，而不是用 `text.index(chunk)` 反查位置：
    反查会命中该片段在文件里的第一次出现，两处相同注释时就会错位替换，
    甚至替换到无关代码上。
    """
    result = list(text)
    # `re.M` is required: without it `$` anchors to the end of the whole string,
    # so a `//` annotation in the middle of a file never matches and the answer
    # it writes is simply left in the source.
    pattern = re.compile(r'(?://|/\*)[^\n]*?<yes>[^\n]*?(?:\*/|$)', re.M)
    for match in pattern.finditer(text):
        for offset in range(match.start(), match.end()):
            # 保留换行，避免行号与字节偏移发生偏移。
            if result[offset] != '\n':
                result[offset] = ' '
    return ''.join(result)


def annotated_classes(text: str) -> tuple[list[str], list[str]]:
    """返回 (本项目类别名, 未识别的原始拼写)。

    未识别的拼写原样返回而不是丢掉：丢掉会让它看起来像"这个样本没有标注"。
    """
    mapped: list[str] = []
    unknown: list[str] = []
    for match in ANNOTATION_RE.finditer(text):
        for raw in match.group('classes').split(','):
            name = raw.strip().upper()
            if not name:
                continue
            target = SB_CURATED_CLASS_MAP.get(name)
            if target is None:
                unknown.append(name)
            elif target not in mapped:
                mapped.append(target)
    return sorted(mapped), sorted(set(unknown))


def _canonical(name: str) -> str:
    """把 ground-truth 的复数拼写归一到检测器的单数拼写。"""
    text = name.strip().lower()
    return text[:-1] if text == 'unchecked_low_level_calls' else text


def load_cases(contracts: Path) -> list[dict]:
    cases = []
    if not contracts.is_dir():
        return cases
    for directory in sorted(contracts.iterdir()):
        truth_path = directory / 'ground-truth.json'
        if not directory.is_dir() or not truth_path.is_file():
            continue
        truth = json.loads(truth_path.read_text(encoding='utf-8'))
        source_name = truth.get('sourceFile') or truth.get('bundlePath')
        if not source_name:
            continue
        source_path = directory / source_name
        if not source_path.is_file():
            continue
        raw = source_path.read_text(encoding='utf-8')
        annotated, unknown = annotated_classes(raw)
        cases.append({
            'caseId': directory.name,
            'sourceFile': source_name,
            'sourceSha256': hashlib.sha256(source_path.read_bytes()).hexdigest(),
            'annotationSourceVerified': truth.get('sourceVerified')
                if 'sourceVerified' in truth else None,
            'knownIssues': sorted(truth.get('knownIssues') or []),
            'annotatedClasses': annotated,
            'unknownAnnotationSpellings': unknown,
        })
    return cases


def compare(cases: list[dict]) -> dict:
    rows = []
    annotated_only = []
    known_only = []
    unknown_spellings = {}
    for case in cases:
        known = {_canonical(item) for item in case['knownIssues']}
        annotated = set(case['annotatedClasses'])
        # 归一后仍不相等的部分。
        missing_from_known = sorted(annotated - known)
        missing_from_ground_truth = sorted(known - annotated)
        for item in case['unknownAnnotationSpellings']:
            unknown_spellings.setdefault(item, []).append(case['caseId'])
        if missing_from_known:
            annotated_only.append({'caseId': case['caseId'], 'classes': missing_from_known})
        if missing_from_ground_truth:
            known_only.append({'caseId': case['caseId'], 'classes': missing_from_ground_truth})
        rows.append({**case, 'knownIssuesCanonical': sorted(known),
                     'annotationNotInKnownIssues': missing_from_known,
                     'knownIssuesWithoutAnnotation': missing_from_ground_truth})
    return {
        'schemaVersion': 1,
        'taxonomy': 'DASP-10 (SmartBugs SB Curated inline annotations)',
        'scope': '只报告标注与 ground-truth 的差异，不改写任何标注或 ground-truth',
        'caseCount': len(cases),
        'annotatedCaseCount': sum(1 for case in cases if case['annotatedClasses']),
        'cases': rows,
        'annotationNotInKnownIssues': annotated_only,
        'knownIssuesWithoutAnnotation': known_only,
        'unknownAnnotationSpellings': {key: sorted(value)
                                       for key, value in sorted(unknown_spellings.items())},
        'classMap': SB_CURATED_CLASS_MAP,
        'interpretation': {
            'annotationNotInKnownIssues': '源码带此标注但 knownIssues 未收录；可能是刻意排除，也可能是漏录，需人工裁定。',
            'knownIssuesWithoutAnnotation': 'knownIssues 收录了源码没有标注的性质；本项目自建样本属正常，SB Curated 样本需核对。',
            'unknownAnnotationSpellings': '标注使用了映射表未覆盖的拼写；不会静默并入任何类别。',
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contracts', type=Path, default=CONTRACTS)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--output', type=Path, default=None)
    args = parser.parse_args(argv)
    report = compare(load_cases(args.contracts))
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + '.tmp')
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                             encoding='utf-8')
        temporary.replace(args.output)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    print(f'样本 {report["caseCount"]}，带标注 {report["annotatedCaseCount"]}')
    print(f'标注有但 knownIssues 未收录：{len(report["annotationNotInKnownIssues"])} 个样本')
    for item in report['annotationNotInKnownIssues']:
        print(f'  {item["caseId"]}: {",".join(item["classes"])}')
    print(f'knownIssues 有但源码无标注：{len(report["knownIssuesWithoutAnnotation"])} 个样本')
    for item in report['knownIssuesWithoutAnnotation']:
        print(f'  {item["caseId"]}: {",".join(item["classes"])}')
    if report['unknownAnnotationSpellings']:
        print('未识别的标注拼写：')
        for name, ids in report['unknownAnnotationSpellings'].items():
            print(f'  {name}: {len(ids)} 个样本')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())