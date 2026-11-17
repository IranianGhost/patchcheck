import base64
import itertools
import shutil
import tempfile
import unittest
from pathlib import Path

from _tmp import mktempdir
from patchcheck.analysis import analyze, correlate, match_failure
from patchcheck.decision import decide, functional_pair
from patchcheck.oracle import evaluate_oracle
from patchcheck.store import digest, write_json


class DecisionTests(unittest.TestCase):
    def test_all_code_combinations_preserve_precedence(self):
        # Dropping any axis or reordering priorities must fail this truth table.
        for flags in itertools.product((False, True), repeat=4):
            technical, security, regression, incomplete = flags
            axes = dict(technical_error=technical, confirmed_security_issue=security,
                        functional_regression=regression, incomplete=incomplete,
                        baseline_reproduced=True, hardening_degraded=False)
            want = 30 if technical else 10 if security else 20 if regression else 40 if incomplete else 0
            self.assertEqual(decide(axes), want, flags)

    def test_missing_baseline_and_hardening_cannot_pass(self):
        self.assertEqual(decide({'baseline_reproduced': False}), 40)
        self.assertEqual(decide({'baseline_reproduced': True, 'hardening_degraded': True}), 40)

    def test_oracle_truth_table(self):
        for base, candidate, want in [('pass', 'pass', 'preserved'), ('pass', 'fail', 'regression'),
                                      ('fail', 'fail', 'both_fail'), ('unknown', 'pass', 'unknown'),
                                      ('fail', 'pass', 'baseline_fail')]:
            self.assertEqual(functional_pair(base, candidate, 'valid'), want)
        self.assertEqual(functional_pair('pass', 'fail', 'invalid'), 'invalid_behavior_changed')


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.root = mktempdir()
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / 'stdout').write_bytes(b'\x00\xff\n')
        (self.root / 'stderr').write_bytes(b'')
        self.run = {'exit_code': 2, 'signal': None, 'timeout': False, 'runner_error': None,
                    'resource_status': 'ok', 'output_truncated': False,
                    'stdout': 'stdout', 'stderr': 'stderr'}
        self.oracle = {'schema_version': '1.0', 'provenance': {'source': 'independent fixture specification',
                       'independent': True}, 'exit_code': 2,
                       'stdout': {'mode': 'exact', 'base64': base64.b64encode(b'\x00\xff\n').decode()}}

    def test_binary_exact_and_expected_nonzero_are_valid(self):
        self.assertEqual(evaluate_oracle(self.run, self.oracle, self.root)['status'], 'pass')
        (self.root / 'stdout').write_bytes(b'\x00\xfe\n')
        self.assertEqual(evaluate_oracle(self.run, self.oracle, self.root)['status'], 'fail')

    def test_missing_or_incomplete_evidence_is_unknown(self):
        self.assertEqual(evaluate_oracle(self.run, None, self.root)['status'], 'unknown')
        self.run['output_truncated'] = True
        self.assertEqual(evaluate_oracle(self.run, self.oracle, self.root)['status'], 'unknown')

    def test_regex_and_structured_json(self):
        (self.root / 'stdout').write_bytes(b'{"a":2,"b":1}\n')
        self.oracle['stdout'] = {'mode': 'json', 'value': {'b': 1, 'a': 2}}
        self.assertEqual(evaluate_oracle(self.run, self.oracle, self.root)['status'], 'pass')
        self.oracle['stdout'] = {'mode': 'regex', 'pattern': r'\{"a":2,"b":1\}\n'}
        self.assertEqual(evaluate_oracle(self.run, self.oracle, self.root)['status'], 'pass')

    def test_nonindependent_oracle_is_unknown(self):
        self.oracle['provenance']['independent'] = False
        self.assertEqual(evaluate_oracle(self.run, self.oracle, self.root)['status'], 'unknown')


class AnalysisTests(unittest.TestCase):
    def test_signal_alone_is_unknown_and_correlate_does_not_invent_causality(self):
        result = analyze({'id': 'r', 'signal': 11, 'resource_status': 'ok'}, b'x')
        self.assertFalse(result['complete'])
        self.assertEqual(result['observations'][0]['confirmation'], 'unclassified')
        self.assertIsNone(result['observations'][0]['signature'])
        self.assertEqual(correlate({'hunks': []}, [{'id': 'f'}], [])[0]['relation'], 'unknown')

    def test_signature_matching_requires_type_and_location(self):
        expected = {'error_type': 'fixture-marker', 'location': 'marker-check', 'key': 'MARK'}
        finding = {'signature': expected, 'confirmation': 'fixture', 'complete_evidence': True}
        self.assertEqual(match_failure(expected, finding), 'match')
        finding['signature'] = {**expected, 'location': 'other'}
        self.assertEqual(match_failure(expected, finding), 'mismatch')
        finding['signature'] = {**expected, 'error_type': 'unknown'}
        self.assertEqual(match_failure(expected, finding), 'unknown')
        self.assertEqual(match_failure(expected, None), 'unknown')


if __name__ == '__main__':
    unittest.main()
