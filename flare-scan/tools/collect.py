#!/usr/bin/env python3
"""Inventory local Solidity sources, excluding dependencies and generated files."""
import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EXCLUDED = {'node_modules', '.git', 'lib', 'out', 'cache', 'artifacts', 'test', 'tests', 'mocks', 'mock', '__pycache__'}


def collect(base=BASE):
    projects = []
    for project in sorted((base / 'contracts').iterdir()):
        if not project.is_dir():
            continue
        sources = []
        for root, dirs, files in os.walk(project):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.startswith('.'))
            for name in sorted(files):
                if name.endswith('.sol'):
                    sources.append(str((Path(root) / name).relative_to(base)))
        projects.append({'project': project.name, 'sourceCount': len(sources), 'sources': sources,
                         'status': 'available' if sources else 'no_solidity_sources'})
    return {'schemaVersion': 1, 'scope': 'Local source inventory, not deployed contract addresses', 'projects': projects}


if __name__ == '__main__':
    print(json.dumps(collect(), indent=2, ensure_ascii=False))
