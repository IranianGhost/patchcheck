"""Verdict rules of pipeline.compare_report on small synthetic reports."""
import unittest

from patchcheck.decision import decide
from patchcheck.pipeline import compare_report

TARGET = {'error_type': 'heap-buffer-overflow', 'location': 'p.c:copy', 'key': 'WRITE'}


def crash(signature=TARGET, error_type=None, method='asan'):
    """A confirmed detector observation; signature=None models a release build."""
    return {'error_type': error_type or (signature or TARGET)['error_type'], 'detection_method': method,
            'confirmation': 'confirmed', 'signature': signature, 'complete_evidence': signature is not None,
            'location': None, 'access': None}


def bare_signal():
    return {'error_type': 'segmentation-fault', 'detection_method': 'os-signal', 'confirmation': 'unclassified',
            'signature': None, 'complete_evidence': False, 'location': None, 'access': None}


def report_for(cases):
    """cases: test id -> (category, signature, {(version, build): (oracle status, observation or None)})"""
    report = {'tests': [], 'runs': [], 'diff': {}, 'technical_errors': [], 'replays': [], 'unstable': [],
              'fixture': False}
    for test_id, (category, signature, cells) in cases.items():
        report['tests'].append({'id': test_id, 'category': category, 'signature': signature, 'regression': None})
        for version in ('base', 'candidate'):
            for build in ('release', 'sanitized'):
                status, obs = cells.get((version, build), ('pass', None))
                report['runs'].append({'id': f'{test_id}-{version}-{build}', 'test_id': test_id, 'version': version,
                                       'build_type': build, 'replay_of': None, 'oracle': {'status': status},
                                       'analysis': {'observations': [obs] if obs else []},
                                       'stdout': 'o', 'stderr': 'e', 'signal': 6 if obs else None,
                                       'resource_status': 'ok'})
    return compare_report(report)


def poc(candidate_sanitized=None, candidate_release=None):
    """Security test: base crashes in both builds; candidate as given."""
    return ('original', TARGET, {
        ('base', 'sanitized'): ('fail', crash()),
        ('base', 'release'): ('fail', crash(None, 'buffer-overflow', 'fortify-source')),
        ('candidate', 'sanitized'): candidate_sanitized or ('pass', None),
        ('candidate', 'release'): candidate_release or ('pass', None)})


VALID = ('valid', None, {})
BOUNDARY = ('boundary', None, {})
INVALID = ('invalid', None, {})
# The full required functional coverage (spec §3.2): valid + boundary + invalid.
FUNCTIONAL = {'valid': VALID, 'boundary': BOUNDARY, 'invalid': INVALID}


class VerdictTests(unittest.TestCase):
    def test_correct_patch_passes(self):
        report = report_for({'poc': poc(), 'ok': VALID, **FUNCTIONAL})
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['axes']['security']['status'], 'fixed')
        self.assertEqual({f['status'] for f in report['findings']}, {'Fixed'})
        self.assertTrue(report['axes']['completeness']['complete'])

    def test_same_crash_on_candidate_is_incomplete_fix(self):
        report = report_for({'poc': poc(('fail', crash()),
                                        ('fail', crash(None, 'buffer-overflow', 'fortify-source'))), 'ok': VALID, **FUNCTIONAL})
        self.assertEqual(report['exit_code'], 10)
        statuses = {f['id']: f['status'] for f in report['findings']}
        self.assertEqual(statuses['finding-security-poc-sanitized'], 'Incomplete Fix')
        self.assertEqual(statuses['finding-security-poc-release'], 'Incomplete Fix')

    def test_different_crash_on_candidate_is_new_issue(self):
        other = crash({'error_type': 'use-after-free', 'location': 'p.c:other', 'key': 'READ'})
        report = report_for({'poc': poc(('fail', other)), 'ok': VALID, **FUNCTIONAL})
        self.assertEqual(report['exit_code'], 10)
        self.assertIn('finding-security-poc-sanitized', report['axes']['security']['confirmed_issues'])
        self.assertEqual(report['findings'][-1]['status'], 'New Issue')

    def test_candidate_only_crash_on_valid_input_is_new_issue(self):
        report = report_for({'poc': poc(), 'ok': ('valid', None, {('candidate', 'sanitized'): ('fail', crash())}), **FUNCTIONAL})
        self.assertEqual(report['exit_code'], 10)
        new_issue = [f for f in report['findings'] if f['status'] == 'New Issue']
        self.assertTrue(new_issue)
        for f in new_issue:
            entry = next(s for s in report['minimization_scope'] if s['finding_id'] == f['id'])
            self.assertFalse(entry['covered'])
            self.assertIn('not minimizable', entry['reason'])

    def test_valid_test_broken_by_patch_is_regression(self):
        report = report_for({'poc': poc(), 'ok': ('boundary', None, {('candidate', 'release'): ('fail', None),
                                                                     ('candidate', 'sanitized'): ('fail', None)}), **FUNCTIONAL})
        self.assertEqual(report['exit_code'], 20)
        self.assertEqual(report['axes']['functional']['status'], 'regression')

    def test_security_issue_takes_precedence_over_regression(self):
        report = report_for({'poc': poc(('fail', crash())),
                             'ok': ('valid', None, {('candidate', 'sanitized'): ('fail', None)}), **FUNCTIONAL})
        self.assertEqual(report['exit_code'], 10)

    def test_base_not_reproduced_is_inconclusive(self):
        report = report_for({'poc': ('original', TARGET, {}), 'ok': VALID})
        self.assertEqual(report['exit_code'], 40)
        self.assertFalse(report['axes']['security']['baseline_reproduced'])

    def test_base_crash_with_other_signature_does_not_reproduce_target(self):
        other = crash({'error_type': 'heap-buffer-overflow', 'location': 'p.c:elsewhere', 'key': 'WRITE'})
        report = report_for({'poc': ('original', TARGET, {('base', 'sanitized'): ('fail', other)}), 'ok': VALID})
        self.assertEqual(report['exit_code'], 40)

    def test_no_security_tests_is_inconclusive(self):
        self.assertEqual(report_for({'ok': VALID})['exit_code'], 40)

    def test_missing_required_category_is_inconclusive(self):
        report = report_for({'poc': poc(), 'ok': VALID})
        self.assertEqual(report['exit_code'], 40)
        reasons = ' '.join(report['axes']['completeness']['reasons'])
        self.assertIn('missing-test-category: no boundary', reasons)
        self.assertIn('missing-test-category: no invalid', reasons)

    def test_no_functional_tests_is_inconclusive(self):
        report = report_for({'poc': poc()})
        self.assertEqual(report['exit_code'], 40)
        reasons = ' '.join(report['axes']['completeness']['reasons'])
        self.assertIn('missing-test-category', reasons)

    def test_unclassified_base_termination_blocks_a_definite_verdict(self):
        # Sanitized base reproduces, but the release base ends with an unclassified
        # signal; that incomplete cell must force INCONCLUSIVE (40), not PASS.
        cases = {'poc': ('original', TARGET, {
                     ('base', 'sanitized'): ('fail', crash()),
                     ('base', 'release'): ('fail', bare_signal()),
                     ('candidate', 'sanitized'): ('pass', None),
                     ('candidate', 'release'): ('pass', None)}),
                 'ok': VALID, **FUNCTIONAL}
        report = report_for(cases)
        self.assertEqual(report['exit_code'], 40)
        self.assertIn('unclassified-termination', ' '.join(report['axes']['completeness']['reasons']))

    def test_unclassified_candidate_crash_is_inconclusive_not_vulnerable(self):
        report = report_for({'poc': poc(('fail', bare_signal())), 'ok': VALID})
        self.assertEqual(report['exit_code'], 40)
        self.assertIn('Inconclusive', {f['status'] for f in report['findings']})

    def test_valid_test_failing_on_base_blocks_pass(self):
        report = report_for({'poc': poc(), 'ok': ('valid', None, {('base', 'release'): ('fail', None),
                                                                  ('candidate', 'release'): ('fail', None)})})
        self.assertEqual(report['exit_code'], 40)

    def test_invalid_input_behavior_change_blocks_pass_without_regression(self):
        report = report_for({'poc': poc(), 'bad': ('invalid', None, {('candidate', 'release'): ('fail', None)})})
        self.assertEqual(report['exit_code'], 40)
        self.assertEqual(report['axes']['functional']['status'], 'unknown')

    def test_unstable_replay_makes_finding_inconclusive(self):
        report = report_for({'poc': poc(), 'ok': VALID, **FUNCTIONAL})
        report['unstable'] = ['poc']
        compare_report(report)
        self.assertEqual(report['exit_code'], 40)

    def test_fixture_reports_never_pass(self):
        report = report_for({'poc': poc(), 'ok': VALID, **FUNCTIONAL})
        report['fixture'] = True
        self.assertEqual(compare_report(report)['exit_code'], 40)

    def test_technical_error_wins(self):
        report = report_for({'poc': poc(('fail', crash())), 'ok': VALID})
        report['technical_errors'] = ['build failed']
        self.assertEqual(compare_report(report)['exit_code'], 30)


class DecisionPrecedenceTests(unittest.TestCase):
    """Review item 5: the decision engine precedence is 30 > 10 > 20 > 40 > 0."""

    def test_full_precedence_chain(self):
        self.assertEqual(decide({'technical_error': True, 'confirmed_security_issue': True,
                                 'functional_regression': True, 'incomplete': True}), 30)
        self.assertEqual(decide({'confirmed_security_issue': True, 'functional_regression': True,
                                 'incomplete': True}), 10)
        self.assertEqual(decide({'functional_regression': True, 'incomplete': True,
                                 'baseline_reproduced': True}), 20)
        self.assertEqual(decide({'incomplete': True, 'baseline_reproduced': True}), 40)
        self.assertEqual(decide({'hardening_degraded': True, 'baseline_reproduced': True}), 40)
        self.assertEqual(decide({'baseline_reproduced': True}), 0)


if __name__ == '__main__':
    unittest.main()


class GeneratedRegressionBuildTests(unittest.TestCase):
    """A minimized/regression test whose bug only ASan catches: the sanitized
    base must reproduce it, but a silent release base is expected, not a failure."""

    def report(self, release_base_crashes):
        test = {'id': 'gen', 'category': 'minimized', 'signature': TARGET,
                'regression': {'signature': TARGET, 'base_match_required': True,
                               'candidate_absence_and_oracle_required': True}}
        cells = {
            ('base', 'sanitized'): ('fail', crash()),
            ('base', 'release'): ('fail', crash(None, 'buffer-overflow', 'fortify-source')) if release_base_crashes
                                 else ('pass', None),   # release does not surface the bug
            ('candidate', 'sanitized'): ('pass', None),
            ('candidate', 'release'): ('pass', None)}
        report = {'tests': [test], 'runs': [], 'diff': {}, 'technical_errors': [], 'replays': [],
                  'unstable': [], 'fixture': False}
        for version in ('base', 'candidate'):
            for build in ('release', 'sanitized'):
                status, obs = cells[(version, build)]
                report['runs'].append({'id': f'gen-{version}-{build}', 'test_id': 'gen', 'version': version,
                                       'build_type': build, 'replay_of': None, 'oracle': {'status': status},
                                       'analysis': {'observations': [obs] if obs else []},
                                       'stdout': 'o', 'stderr': 'e', 'signal': 6 if obs else None,
                                       'resource_status': 'ok'})
        return compare_report(report)

    def results(self, report):
        return {p['build_type']: p['generated_regression']['status']
                for p in report['axes']['functional']['comparisons'] if 'generated_regression' in p}

    def test_asan_only_bug_passes_with_silent_release_base(self):
        self.assertEqual(self.results(self.report(release_base_crashes=False)),
                         {'release': 'pass', 'sanitized': 'pass'})

    def test_bug_that_also_crashes_release_still_passes(self):
        self.assertEqual(self.results(self.report(release_base_crashes=True)),
                         {'release': 'pass', 'sanitized': 'pass'})

    def test_sanitized_base_must_still_reproduce(self):
        # If even the sanitized base no longer crashes, the regression is not confirmed.
        report = self.report(release_base_crashes=False)
        broken = {'tests': report['tests'], 'runs': [], 'diff': {}, 'technical_errors': [],
                  'replays': [], 'unstable': [], 'fixture': False}
        for run in report['runs']:
            if run['id'] == 'gen-base-sanitized':
                run = {**run, 'oracle': {'status': 'pass'}, 'analysis': {'observations': []}, 'signal': None}
            broken['runs'].append(run)
        from patchcheck.pipeline import compare_report as cr
        out = cr(broken)
        self.assertEqual(self.results(out)['sanitized'], 'unknown')


class CandidateOnlyRegressionBuildTests(unittest.TestCase):
    """A minimized regression for a New Issue (candidate-only): the base stays clean
    and the candidate reproduces the new error signature."""

    def report(self, base_clean=True, candidate_reproduces=True):
        test = {'id': 'gen', 'category': 'minimized', 'signature': TARGET,
                'regression': {'signature': TARGET, 'base_absence_required': True,
                               'candidate_reproduce_required': True}}
        cells = {
            ('base', 'sanitized'): ('pass', None) if base_clean else ('fail', crash()),
            ('base', 'release'): ('pass', None),
            ('candidate', 'sanitized'): ('fail', crash()) if candidate_reproduces else ('pass', None),
            ('candidate', 'release'): ('fail', crash(None, 'buffer-overflow', 'fortify-source'))
            if candidate_reproduces else ('pass', None),
        }
        report = {'tests': [test], 'runs': [], 'diff': {}, 'technical_errors': [], 'replays': [],
                  'unstable': [], 'fixture': False}
        for version in ('base', 'candidate'):
            for build in ('release', 'sanitized'):
                status, obs = cells[(version, build)]
                report['runs'].append({'id': f'gen-{version}-{build}', 'test_id': 'gen', 'version': version,
                                       'build_type': build, 'replay_of': None, 'oracle': {'status': status},
                                       'analysis': {'observations': [obs] if obs else []},
                                       'stdout': 'o', 'stderr': 'e', 'signal': 6 if obs else None,
                                       'resource_status': 'ok'})
        return compare_report(report)

    def results(self, report):
        return {p['build_type']: p['generated_regression']['status']
                for p in report['axes']['functional']['comparisons'] if 'generated_regression' in p}

    def test_candidate_only_regression_passes_when_base_clean_and_candidate_crashes(self):
        report = self.report()
        self.assertEqual(self.results(report), {'release': 'pass', 'sanitized': 'pass'})
        self.assertTrue(any(f['status'] == 'New Issue' for f in report['findings']))
        self.assertEqual(report['exit_code'], 10)

    def test_base_not_clean_makes_it_unknown(self):
        self.assertEqual(self.results(self.report(base_clean=False))['sanitized'], 'unknown')

    def test_candidate_no_longer_reproduces_makes_it_unknown(self):
        self.assertEqual(self.results(self.report(candidate_reproduces=False))['sanitized'], 'unknown')

    def test_security_new_issue_is_minimizable_when_base_clean_and_candidate_reproduces(self):
        cells = {
            ('base', 'sanitized'): ('pass', None),
            ('base', 'release'): ('pass', None),
            ('candidate', 'sanitized'): ('fail', crash()),
            ('candidate', 'release'): ('fail', crash(None, 'buffer-overflow', 'fortify-source')),
        }
        report = report_for({'ni': ('original', TARGET, cells), 'ok': VALID, **FUNCTIONAL})
        new_issue = [f for f in report['findings'] if f['status'] == 'New Issue']
        self.assertTrue(new_issue)
        for f in new_issue:
            entry = next(s for s in report['minimization_scope'] if s['finding_id'] == f['id'])
            self.assertTrue(entry['covered'])
            self.assertIn('candidate-only finding', entry['reason'])
