"""Line-coverage evidence for functional-regression patch correlation."""
import unittest
from unittest.mock import patch

from patchcheck.coverage import covered_changes, parse_gcov
from patchcheck.pipeline import _normalize_coverage
from patchcheck.analysis import correlate


class ParseGcovTests(unittest.TestCase):
    def test_gcov_file_format(self):
        text = ('        -:    0:Source:tlvparse.c\n'
                '        1:    5:static int f(void) {\n'
                '        1:    6:    return 1;\n'
                '    #####:    7:    return 0;\n'
                '        -:    8:}\n')
        self.assertEqual(parse_gcov(text), {'tlvparse.c': {5, 6}})

    def test_gcov_stdout_file_header(self):
        text = ("File 'p.c'\n        -:    0:Source:p.c\n        2:   10:int main() {\n    #####:   11:  dead();\n")
        self.assertEqual(parse_gcov(text), {'p.c': {10}})

    def test_never_executed_lines_are_not_covered(self):
        self.assertEqual(parse_gcov('        -:    0:Source:p.c\n    #####:    9:int x;\n'), {'p.c': set()})


class CoveredChangesTests(unittest.TestCase):
    def hunk(self, file='p.c', added=(10,), function='emit'):
        return {'id': 'h1', 'file': file, 'old_file': file, 'removed': [], 'added': list(added),
                'functions': [{'version': 'candidate', 'file': file, 'function': function,
                               'short': function, 'start': 8, 'end': 12}]}

    def test_covered_changed_line_is_reported(self):
        hits = covered_changes([self.hunk(added=(10, 11))], {'p.c': {10}})
        self.assertEqual(hits, [{'hunk_id': 'h1', 'file': 'p.c', 'covered_lines': [10], 'functions': ['emit']}])

    def test_uncovered_changed_line_is_omitted(self):
        self.assertEqual(covered_changes([self.hunk(added=(10, 11))], {'p.c': {99}}), [])

    def test_removed_lines_are_checked_on_the_base_side(self):
        hunk = self.hunk(added=[])
        hunk['removed'] = [7]
        hunk['old_file'] = 'old.c'
        hits = covered_changes([hunk], {'old.c': {7}}, version='base')
        self.assertEqual(hits[0]['covered_lines'], [7])


class NormalizeCoverageTests(unittest.TestCase):
    def test_exact_and_unique_basename_match(self):
        out, amb = _normalize_coverage({'p.c': {1}}, {'p.c'}, ('p.c',))
        self.assertEqual(out, {'p.c': {1}})
        self.assertEqual(amb, [])
        out, amb = _normalize_coverage({'/work/p.c': {1}}, {'p.c'}, ('p.c',))
        self.assertEqual(out, {'p.c': {1}})

    def test_unrelated_file_is_dropped(self):
        out, amb = _normalize_coverage({'other.c': {1}}, {'p.c'}, ('p.c', 'other.c'))
        self.assertEqual(out, {})
        self.assertEqual(amb, [])

    def test_ambiguous_basename_is_not_attributed(self):
        # Both a/parser.c and b/parser.c exist in sources; bare "parser.c" is ambiguous.
        out, amb = _normalize_coverage({'parser.c': {5}}, {'a/parser.c', 'b/parser.c'},
                                       ('a/parser.c', 'b/parser.c'))
        self.assertEqual(out, {})
        self.assertEqual(amb, ['parser.c'])

    def test_explicit_path_not_in_diff_is_not_reattributed(self):
        # Coverage for a/parser.c must NOT be attributed to b/parser.c even though
        # only b/parser.c is in the diff (same-named files).
        out, amb = _normalize_coverage({'a/parser.c': {9}}, {'b/parser.c'}, ('a/parser.c', 'b/parser.c'))
        self.assertEqual(out, {})
        self.assertEqual(amb, [])

    def test_bare_basename_ambiguous_with_one_in_diff_is_not_attributed(self):
        # Both a/parser.c and b/parser.c in sources, only b/parser.c in diff.
        out, amb = _normalize_coverage({'parser.c': {9}}, {'b/parser.c'}, ('a/parser.c', 'b/parser.c'))
        self.assertEqual(out, {})
        self.assertEqual(amb, ['parser.c'])


def oracle(status, failed=()):
    """A structured OracleEvaluation: `checks` maps each compared condition to pass/fail."""
    return {'status': status,
            'checks': {'exit_code': 'exit_code' not in failed, 'stdout': 'stdout' not in failed},
            'source': 'test'}


def run(run_id, test_id, oracle_status='pass', input_sha256='abc', failed=()):
    return {'id': run_id, 'test_id': test_id, 'oracle': oracle(oracle_status, failed),
            'input_sha256': input_sha256, 'exit_code': 2, 'stdout_sha256': 'a' * 64}


class CorrelateFunctionalRegressionTests(unittest.TestCase):
    def finding(self, test_id='valid'):
        return {'id': 'f-functional-valid-release', 'status': 'Functional Regression',
                'base_run_ids': ['b'], 'candidate_run_ids': ['c']}

    def runs(self):
        # candidate oracle 'fail' (on the exit_code check) is the regression.
        return [run('b', 'valid', 'pass'), run('c', 'valid', 'fail', failed=('exit_code',))]

    def hunks(self):
        return [{'id': 'h1', 'file': 'p.c', 'old_file': 'p.c', 'removed': [], 'added': [10],
                 'functions': [{'version': 'candidate', 'file': 'p.c', 'function': 'emit', 'short': 'emit',
                                'start': 8, 'end': 12}]}]

    def relate(self, coverage=None):
        diff = {'hunks': self.hunks(), 'source_map': {'base': {}, 'candidate': {}}}
        if coverage:
            diff['coverage'] = coverage
        return correlate(diff, [self.finding()], self.runs())[0]

    def cov(self, test_id='valid', covered=None, status='ok', reason=None, diagnostic_oracle=None,
            diagnostic_signal=None, diagnostic_timeout=None, diagnostic_output_truncated=None,
            diagnostic_runner_error=None, diagnostic_resource_status='ok', input_sha256='abc',
            ambiguous=None, gcov_failed_files=None, diagnostic_exit_code=2,
            diagnostic_stdout_sha256='a' * 64):
        if diagnostic_oracle is None:
            diagnostic_oracle = oracle('fail', ('exit_code',))
        return {'test_id': test_id, 'coverage': covered or {}, 'run_id': f'cov-{test_id}',
                'status': status, 'reason': reason, 'diagnostic_oracle': diagnostic_oracle,
                'diagnostic_exit_code': diagnostic_exit_code,
                'diagnostic_stdout_sha256': diagnostic_stdout_sha256,
                'diagnostic_signal': diagnostic_signal, 'diagnostic_timeout': diagnostic_timeout,
                'diagnostic_output_truncated': diagnostic_output_truncated,
                'diagnostic_runner_error': diagnostic_runner_error,
                'diagnostic_resource_status': diagnostic_resource_status,
                'input_sha256': input_sha256, 'ambiguous': ambiguous or [],
                'gcov_failed_files': gcov_failed_files or []}

    def test_without_coverage_is_unknown(self):
        self.assertEqual(self.relate()['relation'], 'unknown')

    def test_valid_diagnostic_confirms_covered_line(self):
        rel = self.relate({'build_type': 'coverage', 'runs': [self.cov(covered={'p.c': [10]})]})
        self.assertEqual(rel['relation'], 'confirmed')
        # Review 1.1: hunk id, file and covered lines are structural, not only prose.
        self.assertEqual(rel['hunk_ids'], ['h1'])
        self.assertEqual(rel['locations'][0]['hunk_id'], 'h1')
        self.assertEqual(rel['locations'][0]['file'], 'p.c')
        self.assertEqual(rel['locations'][0]['covered_lines'], [10])
        self.assertIn('covered', rel['evidence'][0])
        self.assertIn('cov-valid', rel['evidence'][0])

    def deletion_relation(self, **diagnostic_changes):
        hunk = self.hunks()[0]
        hunk.update(added=[], removed=[10])
        hunk['functions'][0]['version'] = 'base'
        candidate_coverage = self.cov(covered={'p.c': [10]})
        base_coverage = self.cov(covered={'p.c': [10]}, diagnostic_oracle=oracle('pass'))
        base_coverage.update(version='base', run_id='cov-base', **diagnostic_changes)
        with patch.object(self, 'hunks', return_value=[hunk]):
            return self.relate({'runs': [candidate_coverage, base_coverage]})

    def test_executed_removed_line_links_to_the_passing_baseline(self):
        result = self.deletion_relation()
        self.assertEqual(result['relation'], 'confirmed')
        self.assertEqual(result['hunk_ids'], ['h1'])
        self.assertEqual(result['locations'][0]['version'], 'base')
        self.assertEqual(result['locations'][0]['run_id'], 'cov-base')
        self.assertEqual(result['locations'][0]['role'], 'covered-removed-line')
        self.assertEqual(result['locations'][0]['covered_lines'], [10])

    def test_replacement_uses_base_and_candidate_coverage_independently(self):
        hunk = self.hunks()[0]
        hunk['removed'] = [10]
        base = self.cov(covered={'p.c': [10]}, diagnostic_oracle=oracle('pass'))
        base.update(version='base', run_id='cov-base')
        candidate = self.cov(covered={'p.c': [10]})
        with patch.object(self, 'hunks', return_value=[hunk]):
            result = self.relate({'runs': [candidate, base]})
        self.assertEqual(result['relation'], 'confirmed')
        self.assertEqual(result['hunk_ids'], ['h1'])
        self.assertEqual({(loc['version'], loc['run_id']) for loc in result['locations']},
                         {('base', 'cov-base'), ('candidate', 'cov-valid')})

    def test_removed_line_without_matching_baseline_evidence_stays_unknown(self):
        for changes in [
            {'coverage': {'p.c': [11]}},
            {'input_sha256': 'different'},
            {'diagnostic_oracle': oracle('fail', ('exit_code',))},
            {'diagnostic_timeout': True},
        ]:
            with self.subTest(changes=changes):
                result = self.deletion_relation(**changes)
                self.assertEqual(result['relation'], 'unknown')
                self.assertEqual(result['hunk_ids'], [])

    def test_diagnostic_signal_makes_it_unknown(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, diagnostic_signal=15)]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('terminate cleanly', rel['evidence'][-1])

    def test_diagnostic_timeout_makes_it_unknown(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, diagnostic_timeout=True)]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('terminate cleanly', rel['evidence'][-1])

    def test_unreproduced_oracle_makes_it_unknown(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, diagnostic_oracle=oracle('pass'))]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('did not fail', rel['evidence'][-1])

    def test_different_failing_checks_make_it_unknown(self):
        # main fails on exit_code, diagnostic fails on stdout -> not the same regression.
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]},
                                             diagnostic_oracle=oracle('fail', ('stdout',)))]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('different oracle checks', rel['evidence'][-1])

    def test_same_exit_check_with_a_different_observed_exit_is_unknown(self):
        cov = self.cov(covered={'p.c': [10]}, diagnostic_exit_code=3)
        self.assertEqual(self.relate({'runs': [cov]})['relation'], 'unknown')

    def test_stdout_check_compares_observed_output_hashes(self):
        candidate = run('c', 'valid', 'fail', failed=('stdout',))
        with patch.object(self, 'runs', return_value=[run('b', 'valid'), candidate]):
            for output_hash, expected in [('a' * 64, 'confirmed'), ('b' * 64, 'unknown'), (None, 'unknown')]:
                with self.subTest(output_hash=output_hash):
                    cov = self.cov(covered={'p.c': [10]}, diagnostic_oracle=oracle('fail', ('stdout',)),
                                   diagnostic_stdout_sha256=output_hash)
                    self.assertEqual(self.relate({'runs': [cov]})['relation'], expected)

    def test_status_only_diagnostic_oracle_makes_it_unknown(self):
        # An older report stored only 'fail' without per-condition detail.
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, diagnostic_oracle='fail')]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('no oracle check detail', rel['evidence'][-1])

    def test_input_hash_mismatch_makes_it_unknown(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, input_sha256='zzz')]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('hash', rel['evidence'][-1])

    def test_coverage_of_a_different_test_is_not_attributed(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(test_id='other', covered={'p.c': [10]})]})
        self.assertEqual(rel['relation'], 'unknown')

    def test_uncovered_changed_line_stays_unknown(self):
        rel = self.relate({'build_type': 'coverage', 'runs': [self.cov(covered={'p.c': [99]})]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('not attributed', rel['evidence'][-1])

    def test_ambiguous_basename_is_reported_not_attributed(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={}, ambiguous=['parser.c'])]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('ambiguous', rel['evidence'][-1])

    def test_gcov_failure_for_cited_file_makes_it_unknown(self):
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, gcov_failed_files=['p.c'])]})
        self.assertEqual(rel['relation'], 'unknown')
        self.assertIn('gcov extraction failed', rel['evidence'][-1])

    def test_gcov_failure_for_unrelated_file_keeps_confirmed(self):
        # The cited file p.c is covered and its gcov succeeded; an unrelated failed
        # file must not invalidate the attribution.
        rel = self.relate({'build_type': 'coverage',
                           'runs': [self.cov(covered={'p.c': [10]}, gcov_failed_files=['other.c'])]})
        self.assertEqual(rel['relation'], 'confirmed')


if __name__ == '__main__':
    unittest.main()
