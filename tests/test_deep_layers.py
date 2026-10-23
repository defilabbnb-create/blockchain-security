"""Tests for the source-level vulnerability evidence and the deep layers.

The corpus carries inline annotations such as ``<yes> <report> REENTRANCY``.  Every
rule here must ignore them, so the first test pins that down: detection has to
work on a source whose comments and strings were stripped, and must not fire on
the annotation text alone.  If a future rule starts matching those markers the
corpus stops being a measurement and becomes an answer key lookup.
"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SVE = _load('source_vuln_evidence', 'source_vuln_evidence.py')
GEN = _load('invariant_gen_deep', 'invariant_gen.py')


class SourceEvidenceTests(unittest.TestCase):
    def test_comments_and_strings_are_blanked_but_offsets_survive(self):
        source = 'a(); // call.value(x)\n/* msg.sender.call() */ b();'
        stripped = SVE.strip_comments_and_strings(source)
        self.assertEqual(len(stripped), len(source))
        self.assertNotIn('call.value', stripped)
        self.assertNotIn('msg.sender', stripped)
        self.assertEqual(stripped.count('\n'), source.count('\n'))

    def test_annotation_text_alone_is_never_evidence(self):
        # A file whose only "signals" are corpus annotations must produce nothing.
        annotated = ('// <yes> <report> REENTRANCY\n'
                     '/* <yes> <report> UNCHECKED_LL_CALLS */\n'
                     'contract C { function f() public {} }\n')
        observed = SVE.observe(annotated)
        self.assertEqual(observed['uncheckedCallCount'], 0)
        self.assertEqual(observed['reentrancyCandidateCount'], 0)
        self.assertFalse(observed['blockDerivedValue'])

    def test_unchecked_and_checked_calls_are_distinguished(self):
        unchecked = 'contract C { function f(address c) public { c.call(); } }'
        checked = ('contract C { function f(address c) public {'
                   ' require(c.call()); } }')
        bound = ('contract C { function f(address c) public {'
                 ' (bool ok, ) = c.call{value: 1}(); require(ok); } }')
        self.assertEqual(SVE.observe(unchecked)['uncheckedCallCount'], 1)
        self.assertEqual(SVE.observe(checked)['uncheckedCallCount'], 0)
        self.assertEqual(SVE.observe(bound)['uncheckedCallCount'], 0)

    def test_chained_legacy_value_call_is_recognised_as_value_bearing(self):
        source = ('contract C { function w() public {'
                  ' (bool ok, ) = msg.sender.call.value(1)(); require(ok);'
                  ' balances[msg.sender] = 0; } }')
        observed = SVE.observe(source)
        self.assertEqual(observed['valueCallCount'], 1)
        # The value form is recognised even though the result is bound.
        self.assertEqual(observed['uncheckedCallCount'], 0)

    def test_write_after_transfer_is_a_reentrancy_candidate(self):
        vulnerable = ('contract C { mapping(address => uint) public balances;'
                      ' function w() public {'
                      ' if (balances[msg.sender] >= 1) {'
                      '   (bool ok, ) = msg.sender.call{value: 1}();'
                      '   balances[msg.sender] -= 1; } } }')
        safe = ('contract C { mapping(address => uint) public balances;'
                ' function w() public {'
                '   balances[msg.sender] -= 1;'
                '   (bool ok, ) = msg.sender.call{value: 1}(); require(ok); } }')
        self.assertEqual(SVE.observe(vulnerable)['reentrancyCandidateCount'], 1)
        # Effects-Sent-Effects ordering must not be reported.
        self.assertEqual(SVE.observe(safe)['reentrancyCandidateCount'], 0)

    def test_block_derived_value_and_timestamp_gate_are_separate_signals(self):
        source = ('contract C { function w() public {'
                  ' require(now > deadline); } }')
        observed = SVE.observe(source)
        self.assertTrue(observed['blockDerivedValue'])
        self.assertTrue(observed['timestampGatesPayout'])
        # A mere clock reading is not a payout gate.
        merely = 'contract C { function w() public { last = now; } }'
        self.assertFalse(SVE.observe(merely)['timestampGatesPayout'])

    def test_empty_and_non_string_inputs_do_not_raise(self):
        self.assertEqual(SVE.observe('')['uncheckedCallCount'], 0)
        self.assertEqual(SVE.observe(None)['uncheckedCallCount'], 0)

    def test_erc20_transfer_is_not_a_low_level_call(self):
        # `transfer` is also an ordinary ERC20 method name.  The builtin low-level
        # `transfer(uint256)` takes one argument; `IERC20.transfer(address,uint256)`
        # takes two, and its return value is the contract's business, not a
        # discarded low-level failure.  Reporting the latter made `05-BECToken`
        # -- whose ground truth is arithmetic only -- also report an unchecked
        # low-level call.
        erc20 = ('contract C { IERC20 token; function f(address to) public {'
                 ' token.transfer(to, 1); } }')
        self.assertEqual(SVE.observe(erc20)['uncheckedCallCount'], 0)
        # The builtin form, same method name, one argument, is a low-level call.
        builtin = ('contract C { function f() public {'
                   ' owner.transfer(this.balance); } }')
        self.assertEqual(SVE.observe(builtin)['uncheckedCallCount'], 1)

    def test_checked_erc20_transfer_is_never_unchecked(self):
        source = ('contract C { IERC20 token; function f(address to) public {'
                  ' require(token.transfer(to, 1)); } }')
        self.assertEqual(SVE.observe(source)['uncheckedCallCount'], 0)

    def test_front_running_is_not_the_same_observation_as_an_unchecked_call(self):
        # The rule used to read `uncheckedCallCount`, so every contract with a
        # discarded `transfer` also reported front running -- a different class,
        # reported for the wrong reason.
        one_shot = ('contract C { bool public claimed; uint public reward;'
                    ' function claim() public { require(!claimed);'
                    ' msg.sender.transfer(reward); claimed = true; } }')
        observed = SVE.observe(one_shot)
        self.assertTrue(observed['frontRunning'])
        self.assertGreater(observed['uncheckedCallCount'], 0)

    def test_ordinary_withdrawal_is_not_front_running(self):
        # No one-shot claim: the payout is not pre-emptable by ordering, so the
        # looser "looks like a withdrawal" reading must not fire.
        plain = ('contract C { address owner; function withdraw() public {'
                 ' require(msg.sender == owner);'
                 ' owner.transfer(this.balance); } }')
        self.assertFalse(SVE.observe(plain)['frontRunning'])

    def test_front_running_requires_the_guard_and_the_flag_to_name_one_field(self):
        # `require(!a)` guarding a payment whose body sets an unrelated `b` is
        # not the one-shot claim shape.
        unrelated = ('contract C { bool a; bool b; function f() public {'
                     ' require(!a); msg.sender.transfer(1); b = true; } }')
        self.assertFalse(SVE.observe(unrelated)['frontRunning'])

    def test_front_running_key_present_when_empty(self):
        self.assertIn('frontRunning', SVE.observe(''))
        self.assertFalse(SVE.observe('')['frontRunning'])


class MissingDaspClassTests(unittest.TestCase):
    """short_addresses / incorrect_interface / oracle_stale_price had no anchor."""

    def _keys(self):
        empty = SVE.observe('')
        for key in ('shortAddressPropagation', 'incorrectInterfaceUse', 'oracleStalePrice'):
            self.assertIn(key, empty, key)
            self.assertFalse(empty[key], key)

    def test_every_new_signal_is_present_when_empty(self):
        self._keys()

    def test_repacked_address_is_a_short_address_defect(self):
        # `abi.encodePacked(msg.data, _to)` re-encodes the callee address without
        # the ABI's own zero padding, so a short address shifts the arguments.
        vulnerable = ('contract C { function f(address _to) public {'
                      ' (bool ok, ) = _to.call(abi.encodePacked(msg.data, _to));'
                      ' require(ok); } }')
        self.assertTrue(SVE.observe(vulnerable)['shortAddressPropagation'])

    def test_abi_encode_keeps_its_zero_padding(self):
        safe = ('contract C { function f(address _to) public {'
                ' (bool ok, ) = _to.call(abi.encode(_to)); require(ok); } }')
        self.assertFalse(SVE.observe(safe)['shortAddressPropagation'])

    def test_price_without_a_freshness_bound_is_a_stale_price_defect(self):
        stale = ('contract C { uint price; uint updatedAt;'
                 ' function read() external view returns (uint) { return price; }'
                 ' function setPrice(uint next) external { price = next;'
                 ' updatedAt = block.timestamp; } }')
        self.assertTrue(SVE.observe(stale)['oracleStalePrice'])

    def test_freshness_bound_clears_the_stale_price_signal(self):
        fresh = ('contract C { uint price; uint updatedAt;'
                 ' function read() external view returns (uint) {'
                 ' require(block.timestamp - updatedAt < 1 hours); return price; }'
                 ' function setPrice(uint next) external { price = next;'
                 ' updatedAt = block.timestamp; } }')
        self.assertFalse(SVE.observe(fresh)['oracleStalePrice'])

    def test_a_lone_clock_reading_is_not_a_stale_price_defect(self):
        # A timestamp with no price field is a clock reading, not an oracle.
        source = ('contract C { uint updatedAt; function mark() public {'
                  ' updatedAt = block.timestamp; } }')
        self.assertFalse(SVE.observe(source)['oracleStalePrice'])

    def test_clean_controls_stay_silent_on_all_three_new_signals(self):
        contracts = ROOT / 'benchmark' / 'contracts'
        for case in ('31-clean-vault', '32-clean-lending', '33-clean-amm'):
            directory = contracts / case
            if not directory.is_dir():
                self.skipTest(f'{case} not present')
            truth = json.loads((directory / 'ground-truth.json').read_text('utf-8'))
            observed = SVE.observe((directory / truth['sourceFile']).read_text('utf-8'))
            self.assertFalse(observed['shortAddressPropagation'], case)
            self.assertFalse(observed['oracleStalePrice'], case)


class IrOrderingTests(unittest.TestCase):
    """The IR-only reentrancy rule must key on the ledger, not on any later write."""

    def _doc(self, operations):
        return {'schemaVersion': 1, 'functions': [], 'operations': operations}

    def _write(self, variable, expression, start):
        return {'kind': 'state_write', 'variable': variable,
                'expression': expression, 'location': {'start': start}}

    def _call(self, expression, start):
        return {'kind': 'external_call', 'callKind': 'native_send',
                'valueTransferEvidence': {'state': 'unknown', 'expression': expression},
                'location': {'start': start}}

    def test_payout_followed_by_a_one_shot_flag_is_not_reentrancy(self):
        # `winner.send(winAmount); payedOut = true;` -- the write is a flag, not
        # accounting, so a callback cannot drain through it.
        doc = self._doc([self._write('Lotto.payedOut', 'payedOut = true', 10),
                         self._call('winAmount', 20)])
        self.assertFalse(GEN._operation_order(doc)['external_before_write'])

    def test_payout_followed_by_bookkeeping_is_not_reentrancy(self):
        # `msg.sender.transfer(reward); reward = msg.value;`
        doc = self._doc([self._call('reward', 10),
                         self._write('C.reward', 'reward = msg.value', 20)])
        self.assertFalse(GEN._operation_order(doc)['external_before_write'])

    def test_payout_followed_by_a_ledger_update_is_reentrancy(self):
        # `msg.sender.call{value: bal}(); balances[msg.sender] = 0;`
        doc = self._doc([self._call('bal', 10),
                         self._write('C.balances', 'balances[msg.sender] = 0', 20)])
        self.assertTrue(GEN._operation_order(doc)['external_before_write'])

    def test_explicit_declaration_still_wins(self):
        # An IR that declares the order explicitly is trusted over inference.
        doc = self._doc([])
        doc['callBeforeStateUpdate'] = True
        self.assertTrue(GEN._operation_order(doc)['external_before_write'])


class RoleDetectionTests(unittest.TestCase):
    def test_zero_argument_getter_is_required_for_a_read_parameter(self):
        document = {'schemaVersion': 1, 'functions': [
            {'name': 'V.balanceOf(address)', 'entrypoint': True},
            {'name': 'V.totalSupply()', 'entrypoint': True}],
            'storageAccesses': []}
        # balanceOf(address) takes a parameter, so it cannot be staticcalled bare.
        self.assertIsNone(GEN._first_getter(document['functions'], 'balanceOf'))
        self.assertEqual(GEN._first_getter(document['functions'], 'totalSupply'),
                         'totalSupply')

    def test_parameterised_entrypoint_is_not_offered_as_a_selector(self):
        document = {'schemaVersion': 1, 'functions': [
            {'name': 'V.withdraw(uint256)', 'entrypoint': True},
            {'name': 'V.rescue()', 'entrypoint': True}]}
        self.assertIsNone(GEN._first_entrypoint(document['functions'], 'withdraw'))
        self.assertEqual(GEN._first_entrypoint(document['functions'], 'withdraw', 'rescue'),
                         'rescue()')

    def test_role_detection_without_source_falls_back_to_ir_only_evidence(self):
        document = {'schemaVersion': 1, 'functions': [
            {'name': 'V.totalSupply()', 'entrypoint': True},
            {'name': 'V.deposit(uint256)', 'entrypoint': True},
            {'name': 'V.redeem(uint256)', 'entrypoint': True}],
            'storageAccesses': [
                {'effect': {'variable': 'V.totalAssets'}},
                {'effect': {'variable': 'V.totalSupply'}}]}
        roles, _ = GEN.detect_roles(document)
        self.assertIn('erc4626', roles)

    def test_detection_is_stable_with_and_without_source_text(self):
        document = {'schemaVersion': 1, 'functions': [
            {'name': 'R.balanceOf(address)', 'entrypoint': True}],
            'storageAccesses': [], 'operations': []}
        without = GEN.generate_invariants(document)
        with_source = GEN.generate_invariants(
            document, source_text='contract R { }')
        self.assertEqual(without['state'], with_source['state'])


class BenchmarkCorpusTests(unittest.TestCase):
    """The corpus is the measurement; these tests only assert what it contains."""

    def test_clean_samples_produce_no_reentrancy_or_unchecked_call(self):
        contracts = ROOT / 'benchmark' / 'contracts'
        for case in ('31-clean-vault', '32-clean-lending', '33-clean-amm'):
            directory = contracts / case
            if not directory.is_dir():
                self.skipTest(f'{case} not present')
            ground_truth = json.loads((directory / 'ground-truth.json').read_text('utf-8'))
            self.assertEqual(ground_truth.get('knownIssues'), [])
            source = (directory / ground_truth['sourceFile']).read_text('utf-8')
            observed = SVE.observe(source)
            self.assertEqual(observed['reentrancyCandidateCount'], 0, case)
            self.assertEqual(observed['uncheckedCallCount'], 0, case)

    def test_known_reentrancy_samples_are_detected(self):
        contracts = ROOT / 'benchmark' / 'contracts'
        detected = 0
        present = 0
        for directory in sorted(contracts.iterdir()):
            truth_path = directory / 'ground-truth.json'
            if not truth_path.is_file():
                continue
            ground_truth = json.loads(truth_path.read_text('utf-8'))
            if 'reentrancy' not in (ground_truth.get('knownIssues') or []):
                continue
            source = (directory / ground_truth['sourceFile']).read_text('utf-8')
            present += 1
            if SVE.observe(source)['reentrancyCandidateCount'] > 0:
                detected += 1
        self.assertGreater(present, 0, 'corpus has no reentrancy samples')
        # Recorded as a floor rather than a perfect score: this is a measurement,
        # and a lower number must stay visible instead of being tuned away.
        self.assertGreaterEqual(detected, present * 0.6,
                                f'detected {detected}/{present} reentrancy samples')


if __name__ == '__main__':
    unittest.main()