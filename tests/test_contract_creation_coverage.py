import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('review_static_creation', ROOT / 'scripts' / 'review-static.py')
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)


class NewContract:
    """Small Slither-IR-shaped fixture; the production IR class has this name."""

    def __init__(self, created, value=None, salt=None):
        self.contract_created = SimpleNamespace(name=created)
        self.call_value = value
        self.call_salt = salt

    def __str__(self):
        return f'TMP = new {self.contract_created.name}'


def source_location(line):
    return SimpleNamespace(
        filename=SimpleNamespace(relative='Factory.sol', short='Factory.sol'),
        lines=[line],
    )


class ContractCreationCoverageTests(unittest.TestCase):
    def test_real_slither_factory_ir_exposes_create_and_create2_paths(self):
        with tempfile.TemporaryDirectory(prefix='factory creation coverage ') as folder:
            base = Path(folder)
            (base / 'Factory.sol').write_text(
                'pragma solidity 0.8.28; '
                'contract Child { constructor() payable {} } '
                'contract Factory {'
                'function create() external payable returns(address) {'
                'return address(new Child{value: msg.value}());}'
                'function create2(bytes32 salt) external payable returns(address) {'
                'return address(new Child{salt:salt,value:msg.value}());}'
                '}'
            )
            script = textwrap.dedent('''
                import importlib.util,sys
                from pathlib import Path
                root,base=Path(sys.argv[1]),Path(sys.argv[2]);tools=root/'flare-scan/tools'
                sys.path[:0]=[str(tools/'pylibs'),str(tools)]
                from crytic_compile import CryticCompile
                from crytic_compile.platform.solc import Solc
                from slither.slither import Slither
                spec=importlib.util.spec_from_file_location('review',root/'scripts/review-static.py')
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                compilation=CryticCompile(Solc(str(base/'Factory.sol')),solc=str(tools/'solc-wrapper.sh'),solc_working_dir=str(base),cwd=str(base))
                graph=module.build_call_graph(Slither(compilation).contracts,['Factory'])
                creations=[row['effect'] for row in graph['paths'] if row['effect']['kind']=='contract_creation']
                assert graph['contractCreationPathCount']==2,graph
                assert {row['callKind'] for row in creations}=={'create','create2'},creations
                assert all(row['valueTransferEvidence']['state']=='unknown' for row in creations),creations
            ''')
            run = subprocess.run(
                [sys.executable, '-c', script, str(ROOT), folder],
                capture_output=True,
                text=True,
                timeout=30,
                env=dict(os.environ, SOLC_VERSION='0.8.28'),
            )
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_call_graph_records_create_create2_and_value_evidence_separately(self):
        factory = SimpleNamespace(
            canonical_name='Factory.deploy()',
            contract=SimpleNamespace(name='Factory'),
            visibility='external',
            is_constructor=False,
            is_fallback=False,
            source_mapping=source_location(1),
            modifiers=[],
            nodes=[
                SimpleNamespace(
                    source_mapping=source_location(10),
                    state_variables_written=[],
                    internal_calls=[],
                    high_level_calls=[],
                    low_level_calls=[],
                    irs=[NewContract('Child', SimpleNamespace(value='5'))],
                    expression='new Child{value: 5}()',
                ),
                SimpleNamespace(
                    source_mapping=source_location(11),
                    state_variables_written=[],
                    internal_calls=[],
                    high_level_calls=[],
                    low_level_calls=[],
                    irs=[NewContract('Child', SimpleNamespace(value='0'), salt=SimpleNamespace(name='salt'))],
                    expression='new Child{value: 0, salt: salt}()',
                ),
            ],
        )

        report = STATIC.build_call_graph([SimpleNamespace(name='Factory', functions=[factory])], ['Factory'])
        creations = [row['effect'] for row in report['paths'] if row['effect']['kind'] == 'contract_creation']

        self.assertEqual(report['contractCreationPathCount'], 2)
        self.assertEqual(report['externalCallPathCount'], 0)
        self.assertEqual({row['callKind'] for row in creations}, {'create', 'create2'})
        by_kind = {row['callKind']: row for row in creations}
        self.assertEqual(by_kind['create']['createdContract'], 'Child')
        self.assertEqual(by_kind['create']['valueTransferEvidence']['state'], 'nonzero')
        self.assertTrue(by_kind['create']['sendsValue'])
        self.assertEqual(by_kind['create2']['valueTransferEvidence']['state'], 'zero')
        self.assertFalse(by_kind['create2']['sendsValue'])

    def test_dynamic_correlation_matches_only_the_corresponding_creation_opcode(self):
        source_hash = 'e' * 64
        def site(line):
            start = line * 10
            return STATIC.effect_site_id(source_hash, 'Factory.sol', start, 4, 'contract_creation')
        graph = {
            'paths': [
                {'effect': {'kind': 'contract_creation', 'callKind': 'create', 'sourceSha256': source_hash,
                    'effectSiteId': site(10), 'location': {'file': 'Factory.sol', 'lines': [10], 'start': 100, 'length': 4}}},
                {'effect': {'kind': 'contract_creation', 'callKind': 'create2', 'sourceSha256': source_hash,
                    'effectSiteId': site(11), 'location': {'file': 'Factory.sol', 'lines': [11], 'start': 110, 'length': 4}}},
            ]
        }
        local = {
            'traces': [{
                'transactionHash': '0xcreation',
                'failed': False,
                'targetDepth': 1,
                'effects': [
                    {'depth': 1, 'op': 'CREATE', 'effectSiteId': site(10),
                        'sourceLocation': {'file': 'Factory.sol', 'lineStart': 10, 'lineEnd': 10, 'start': 100, 'length': 4, 'sourceSha256': source_hash}},
                    {'depth': 1, 'op': 'CREATE2', 'effectSiteId': site(11),
                        'sourceLocation': {'file': 'Factory.sol', 'lineStart': 11, 'lineEnd': 11, 'start': 110, 'length': 4, 'sourceSha256': source_hash}},
                    {'depth': 1, 'op': 'CREATE', 'effectSiteId': site(11),
                        'sourceLocation': {'file': 'Factory.sol', 'lineStart': 11, 'lineEnd': 11, 'start': 110, 'length': 4, 'sourceSha256': source_hash}},
                ],
            }]
        }

        report = STATIC.correlate_dynamic_effects(graph, local)

        self.assertEqual(report['matchedEffectCount'], 2)
        self.assertEqual(report['candidatePathPairCount'], 2)
        self.assertEqual({row['opcode'] for row in report['matches']}, {'CREATE', 'CREATE2'})
        create2_match = next(row for row in report['matches'] if row['opcode'] == 'CREATE2')
        self.assertEqual(create2_match['candidatePathIndices'], [1])
        self.assertFalse(any(row['completePathProven'] for row in report['matches']))


if __name__ == '__main__':
    unittest.main()
