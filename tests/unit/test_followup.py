"""Automatic replay/bundle follow-up of run and the replay stability exemption."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from _tmp import tmpdir
from patchcheck.contracts import ConfigError
from patchcheck.pipeline import confirmed_finding_tests, replay_and_bundle, run_pipeline
from patchcheck.replay import stability_required

CRASH = {'error_type': 'heap-buffer-overflow', 'detection_method': 'asan', 'confirmation': 'confirmed'}


def run(run_id, test_id, crash=False):
    return {'id': run_id, 'test_id': test_id, 'analysis': {'observations': [CRASH] if crash else []}}


def finding(base, candidate, confirmation='confirmed', error_type='heap-buffer-overflow'):
    return {'confirmation': confirmation, 'error_type': error_type,
            'base_run_ids': [base], 'candidate_run_ids': [candidate]}


def report(findings, replays=(), bundles=()):
    runs = [run('poc-b', 'poc', True), run('poc-c', 'poc'), run('ok-b', 'ok'), run('ok-c', 'ok'),
            run('odd-b', 'odd'), run('odd-c', 'odd')]
    return {'runs': runs, 'findings': findings, 'replays': list(replays), 'bundles': list(bundles),
            'technical_errors': [], 'fixture': False}


class ConfirmedFindingTests(unittest.TestCase):
    def test_security_and_functional_findings_are_replayed(self):
        value = report([finding('poc-b', 'poc-c'), finding('ok-b', 'ok-c', error_type='functional-regression')])
        self.assertEqual(confirmed_finding_tests(value), ['ok', 'poc'])

    def test_unconfirmed_findings_are_not_replayed(self):
        value = report([finding('odd-b', 'odd-c', confirmation='unknown'),
                        finding('poc-b', 'poc-c', confirmation='fixture')])
        self.assertEqual(confirmed_finding_tests(value), [])


class ReplayAndBundleTests(unittest.TestCase):
    def follow_up(self, value):
        with patch('patchcheck.pipeline.load_report', return_value=value), \
                patch('patchcheck.replay.replay_case') as replay, \
                patch('patchcheck.bundle.make_bundle') as bundle:
            replay_and_bundle(Path('/r/report.json'))
        return replay, bundle

    def test_each_confirmed_test_is_replayed_three_times_then_bundled(self):
        replay, bundle = self.follow_up(report([finding('poc-b', 'poc-c'),
                                                finding('ok-b', 'ok-c', error_type='functional-regression')]))
        self.assertEqual(sorted(call.args[1:] for call in replay.call_args_list), [('ok', 3), ('poc', 3)])
        bundle.assert_called_once_with(Path('/r/report.json'), Path('/r/reproduction.tar.gz'), include_image=False)

    def test_functional_only_follow_up_includes_toolchain_image(self):
        _, bundle = self.follow_up(report([finding('ok-b', 'ok-c', error_type='functional-regression')]))
        bundle.assert_called_once_with(Path('/r/report.json'), Path('/r/reproduction.tar.gz'), include_image=True)

    def test_already_replayed_and_bundled_report_is_left_alone(self):
        replay, bundle = self.follow_up(report([finding('poc-b', 'poc-c')],
                                               replays=[{'test_id': 'poc', 'additional_count_per_cell': 3}],
                                               bundles=['bundles/reproduction.tar.gz']))
        replay.assert_not_called()
        bundle.assert_not_called()

    def test_nothing_confirmed_means_no_replay_and_no_bundle(self):
        replay, bundle = self.follow_up(report([]))
        replay.assert_not_called()
        bundle.assert_not_called()

    def test_failed_follow_up_is_recorded_as_a_technical_error(self):
        config = {'target': 't', 'fixture': False, 'source': {'repo': 'r', 'base': 'b', 'candidate': 'c'},
                  'corpus_dir': 'corpus', 'tests': []}
        saved = report([])
        with tmpdir() as out, \
                patch('patchcheck.pipeline.load_config', return_value=config), \
                patch('patchcheck.pipeline.build_all', return_value=([], {'base': {}, 'candidate': {}, 'diff': {}}, {})), \
                patch('patchcheck.pipeline.prepare_tests', return_value=[]), \
                patch('patchcheck.pipeline.write_json'), \
                patch('patchcheck.pipeline.write_report') as write, \
                patch('patchcheck.pipeline.compare_report') as compare, \
                patch('patchcheck.pipeline.load_report', return_value=saved), \
                patch('patchcheck.pipeline.replay_and_bundle', side_effect=ConfigError('docker gone')):
            result = run_pipeline(Path(out) / 'config.json', Path(out) / 'run')
        self.assertIs(result, saved)
        self.assertEqual(result['technical_errors'], ['replay/bundle follow-up failed: docker gone'])
        compare.assert_called_with(saved)
        self.assertIs(write.call_args.args[0], saved)


class StabilityRequiredTests(unittest.TestCase):
    BASE, CANDIDATE = {'version': 'base'}, {'version': 'candidate'}

    def test_base_of_security_test_without_any_crash_is_exempt(self):
        for category in ('original', 'minimized'):
            self.assertFalse(stability_required({'category': category}, self.BASE, [run('a', 't'), run('b', 't')]))

    def test_base_that_crashed_in_any_record_must_be_stable(self):
        self.assertTrue(stability_required({'category': 'original'}, self.BASE, [run('a', 't'), run('b', 't', True)]))

    def test_candidate_and_functional_tests_must_be_stable(self):
        self.assertTrue(stability_required({'category': 'original'}, self.CANDIDATE, [run('a', 't')]))
        for category in ('valid', 'boundary', 'invalid'):
            self.assertTrue(stability_required({'category': category}, self.BASE, [run('a', 't')]))
