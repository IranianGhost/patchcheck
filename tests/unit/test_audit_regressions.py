import unittest
from pathlib import Path

from _tmp import tmpdir
from patchcheck.analysis import analyze, path_locations
from patchcheck.elf import raw_hardening
from patchcheck.oracle import evaluate_oracle
from patchcheck.pipeline import compare_report
import test_verdict
from test_verdict import VALID, poc, report_for


class AuditRegressions(unittest.TestCase):
    def test_candidate_must_satisfy_security_case_oracle(self):
        for status in ('fail', 'unknown'):
            with self.subTest(status=status):
                report = report_for({'original': poc((status, None)), 'valid': VALID})
                self.assertEqual(report['exit_code'], 40)
                self.assertFalse(report['axes']['completeness']['complete'])

    def test_required_generated_checks_must_contribute_to_verdict(self):
        for cell in ('gen-base-sanitized', 'gen-candidate-sanitized'):
            with self.subTest(cell=cell):
                report = report_for({'original': poc(), 'valid': VALID})
                generated = test_verdict.GeneratedRegressionBuildTests().report(False)
                report['tests'].extend(generated['tests'])
                report['runs'].extend(generated['runs'])
                affected = next(run for run in report['runs'] if run['id'] == cell)
                affected.update(oracle={'status': 'fail'}, signal=None, analysis={'observations': []})
                self.assertEqual(compare_report(report)['exit_code'], 40)

    def test_unqualified_hunk_matching_cannot_cross_cpp_classes_or_versions(self):
        frame = {'project_file': 'p.cc', 'function': 'ns::Reader::read()', 'line': 18}
        path = [('crash-site', 0, frame)]
        span = {'short': 'read', 'function': 'ns::Other::read', 'file': 'p.cc',
                'version': 'base', 'start': 15, 'end': 25}
        hunk = {'id': 'h1', 'functions': [span], 'removed': [19], 'added': [21]}
        self.assertFalse(path_locations('base', path, [hunk], {}))
        span.update(function='ns::Reader::read', version='candidate')
        self.assertFalse(path_locations('base', path, [hunk], {}))
        span.update(version='base')
        self.assertTrue(path_locations('base', path, [hunk], {}))

    def test_bare_sanitizer_header_is_not_confirmed(self):
        for code in (0, 1):
            run = {'build_type': 'sanitized', 'exit_code': code, 'resource_status': 'ok'}
            result = analyze(run, b'==42==ERROR: AddressSanitizer: heap-buffer-overflow\n')
            self.assertEqual(result['observations'][0]['confirmation'], 'unclassified')

    def test_nested_json_booleans_are_distinct_from_numbers(self):
        with tmpdir() as folder:
            root = Path(folder)
            (root / 'stdout').write_text('{"items": [true, 2.0]}')
            run = {'exit_code': 0, 'stdout': 'stdout'}
            oracle = {'schema_version': '1.0', 'provenance': {'independent': True, 'source': 'Test'},
                      'exit_code': 0, 'stdout': {'mode': 'json', 'value': {'items': [1, 2]}}}
            self.assertEqual(evaluate_oracle(run, oracle, root)['status'], 'fail')
            oracle['stdout']['value']['items'][0] = True
            self.assertEqual(evaluate_oracle(run, oracle, root)['status'], 'pass')

    def test_execute_flag_is_read_without_requiring_read_and_write(self):
        for flags in ('E', 'RE', 'RWE'):
            line = 'GNU_STACK 0x000000 0x000000 0x000000 0x000000 0x000000 ' + flags + ' 0x10'
            self.assertEqual(raw_hardening(line)['nx_indicator'], 'executable_stack')
