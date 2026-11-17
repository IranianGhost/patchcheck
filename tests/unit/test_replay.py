import unittest

from patchcheck.contracts import ConfigError
from patchcheck.replay import stability, validate_count


class ReplayTests(unittest.TestCase):
    def test_invalid_oracle_violation_is_not_summarized_as_preserved(self):
        from patchcheck.pipeline import compare_report
        report = {'tests': [{'id': 'bad-input', 'category': 'invalid', 'regression': None}],
                  'runs': [], 'diff': {}, 'technical_errors': [], 'replays': [], 'unstable': []}
        for kind in ('release', 'sanitized'):
            for version, status in [('base', 'pass'), ('candidate', 'fail')]:
                report['runs'].append({'id': version + kind, 'test_id': 'bad-input', 'build_type': kind,
                                      'version': version, 'replay_of': None, 'oracle': {'status': status},
                                      'analysis': {}, 'stdout': 'out', 'stderr': 'err'})
        compare_report(report)
        self.assertEqual(report['axes']['functional']['status'], 'unknown')
        self.assertTrue(all(p['status'] == 'invalid_behavior_changed' for p in report['axes']['functional']['comparisons']))

    def test_three_is_a_minimum_not_an_upper_bound(self):
        for value in (0, 1, 2):
            with self.assertRaises(ConfigError):
                validate_count(value)
        validate_count(3)
        validate_count(5)

    def test_stability_ignores_time_but_compares_outputs_status_and_signature(self):
        run = {'exit_code': 0, 'signal': None, 'timeout': False, 'resource_status': 'ok',
               'output_truncated': False, 'runner_error': None, 'stdout_sha256': 'a',
               'stderr_sha256': 'b', 'analysis': {}, 'duration_seconds': 0.1}
        self.assertEqual(stability([run, {**run, 'duration_seconds': 9}, run])['status'], 'stable')
        for key, value in [('stdout_sha256', 'c'), ('signal', 11), ('timeout', True), ('resource_status', 'memory_limit')]:
            self.assertEqual(stability([run, {**run, key: value}, run])['status'], 'unstable')
        self.assertEqual(stability([run, run])['status'], 'unknown')

    def test_recompare_keeps_unstable_regression_inconclusive(self):
        from patchcheck.pipeline import compare_report
        report = {'tests': [{'id': 'case', 'category': 'valid', 'regression': None}],
                  'runs': [], 'diff': {}, 'technical_errors': [], 'replays': [], 'unstable': []}
        for kind in ('release', 'sanitized'):
            for version, status in [('base', 'pass'), ('candidate', 'fail')]:
                report['runs'].append({'id': version + kind, 'test_id': 'case', 'build_type': kind,
                                      'version': version, 'replay_of': None, 'oracle': {'status': status},
                                      'analysis': {}, 'stdout': 'out', 'stderr': 'err'})
        compare_report(report)
        self.assertEqual(report['axes']['functional']['status'], 'regression')
        report['replays'] = [{'test_id': 'case', 'status': 'unstable'}]
        report['unstable'] = ['case']
        compare_report(report)
        self.assertEqual(report['axes']['functional']['status'], 'unknown')
        self.assertEqual(report['axes']['functional']['decision_engine_code'], 40)
        self.assertTrue(report['findings'])
        self.assertTrue(all(f['status'] == 'Inconclusive' and f['replay_stability'] == 'unstable' for f in report['findings']))
