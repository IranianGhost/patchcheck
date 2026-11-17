import unittest
from unittest.mock import patch

from patchcheck.contracts import ConfigError
from patchcheck.minimize import choose_direction, ddmin


class MinimizeTests(unittest.TestCase):
    def test_only_same_signature_matches_and_alternate_error_is_rejected(self):
        def predicate(data):
            if b'OTHER' in data:
                return 'mismatch'
            return 'match' if b'MARK' in data else 'unknown'
        result = ddmin(b'paddingMARKtail', predicate, max_attempts=100, wall_seconds=10)
        self.assertEqual(result['data'], b'MARK')
        self.assertEqual(result['status'], 'reduced')
        self.assertTrue(result['history'])
        self.assertEqual(predicate(b'OTHER'), 'mismatch')

    def test_unknown_nonzero_and_budget_cannot_register_success(self):
        result = ddmin(b'hello', lambda _: 'unknown', max_attempts=10, wall_seconds=10)
        self.assertEqual(result['status'], 'initial_not_matched')
        result = ddmin(b'xxxxMARKxxxx', lambda data: 'match' if b'MARK' in data else 'mismatch', max_attempts=1, wall_seconds=10)
        self.assertEqual(result['status'], 'budget_exhausted')
        self.assertFalse(result['validated'])

    def test_predicate_finishing_after_deadline_is_not_validated(self):
        with patch('patchcheck.minimize.time.monotonic', side_effect=[0, 0, 2, 2]):
            result = ddmin(b'', lambda _: 'match', max_attempts=3, wall_seconds=1)
        self.assertEqual(result['status'], 'budget_exhausted')
        self.assertFalse(result['validated'])

    def test_reduces_to_the_minimal_trigger(self):
        result = ddmin(b'xxxxYYYYxxxx', lambda d: 'match' if b'YYYY' in d else 'mismatch',
                       max_attempts=200, wall_seconds=10)
        self.assertEqual(result['data'], b'YYYY')
        self.assertEqual(result['status'], 'reduced')
        self.assertTrue(result['validated'])

    def test_already_minimal_input_is_no_reduction(self):
        result = ddmin(b'M', lambda d: 'match' if d == b'M' else 'unknown', max_attempts=20, wall_seconds=10)
        self.assertEqual(result['data'], b'M')
        self.assertEqual(result['status'], 'no_reduction')
        self.assertTrue(result['validated'])

    def test_mismatching_original_is_initial_not_matched(self):
        result = ddmin(b'abcdef', lambda d: 'mismatch', max_attempts=20, wall_seconds=10)
        self.assertEqual(result['status'], 'initial_not_matched')
        self.assertFalse(result['validated'])

    def test_minimized_data_still_satisfies_the_predicate(self):
        def predicate(data):
            return 'match' if b'MARK' in data else 'mismatch'
        result = ddmin(b'AAABBBMARKCCCDDD', predicate, max_attempts=200, wall_seconds=10)
        self.assertEqual(predicate(result['data']), 'match')

    def test_max_attempts_caps_the_number_of_attempts(self):
        result = ddmin(b'Z' * 40, lambda d: 'match' if b'Z' in d else 'mismatch',
                       max_attempts=5, wall_seconds=10)
        self.assertLessEqual(len(result['history']), 5)
        self.assertEqual(result['status'], 'budget_exhausted')
        self.assertFalse(result['validated'])

    def test_history_records_hashes_sizes_and_results(self):
        result = ddmin(b'12MARK34', lambda d: 'match' if b'MARK' in d else 'mismatch',
                       max_attempts=50, wall_seconds=10)
        self.assertTrue(result['history'])
        for entry in result['history']:
            self.assertEqual(set(entry), {'attempt', 'size', 'sha256', 'result', 'elapsed_seconds'})
            self.assertIn(entry['result'], ('match', 'mismatch', 'unknown'))

    def test_predicate_with_an_unexpected_result_is_a_config_error(self):
        with self.assertRaises(ConfigError):
            ddmin(b'data', lambda d: 'yes', max_attempts=10, wall_seconds=10)


class DirectionTests(unittest.TestCase):
    SIGNATURE = {'error_type': 'heap-buffer-overflow', 'location': 'p.c:f', 'key': 'WRITE'}

    def obs(self, signature=None):
        signature = signature if signature is not None else self.SIGNATURE
        return {'error_type': signature['error_type'], 'detection_method': 'asan',
                'confirmation': 'confirmed', 'signature': signature, 'complete_evidence': True,
                'location': None, 'access': None}

    def record(self, *observations):
        return {'analysis': {'observations': list(observations)}}

    def test_base_reproduction_is_base_direction(self):
        self.assertEqual(choose_direction(self.SIGNATURE, self.record(self.obs()), self.record()), 'base')

    def test_candidate_only_is_candidate_direction(self):
        self.assertEqual(choose_direction(self.SIGNATURE, self.record(), self.record(self.obs())), 'candidate')

    def test_both_reproduce_stays_base_direction(self):
        self.assertEqual(choose_direction(self.SIGNATURE, self.record(self.obs()), self.record(self.obs())), 'base')

    def test_candidate_reproduction_with_unclean_base_is_none(self):
        other = {'error_type': 'use-after-free', 'detection_method': 'asan', 'confirmation': 'confirmed',
                 'signature': {'error_type': 'use-after-free', 'location': 'p.c:g', 'key': 'READ'},
                 'complete_evidence': True, 'location': None, 'access': None}
        self.assertIsNone(choose_direction(self.SIGNATURE, self.record(other), self.record(self.obs())))

    def test_neither_reproduces_is_none(self):
        self.assertIsNone(choose_direction(self.SIGNATURE, self.record(), self.record()))
