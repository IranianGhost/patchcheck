"""Hardening interpretation and comparison on real readelf output.

Samples in tests/unit/data/elf/ are re-recorded by record.sh: tlvparse built with
the project release flags (hardened) and with one protection removed at a time.
"""
import unittest
from pathlib import Path

from patchcheck.build import validate_instrumentation
from patchcheck.contracts import ConfigError
from patchcheck.decision import decide
from patchcheck.elf import compare_hardening, instrumentation_markers, interpret, raw_hardening
from patchcheck.pipeline import compare_report

DATA = Path(__file__).resolve().parent / 'data' / 'elf'


def evidence(name):
    return raw_hardening((DATA / f'{name}.txt').read_text())


def build(version, name, flags=('-O2',)):
    return {'id': f'{version}-release', 'version': version, 'build_type': 'release', 'result': 'success',
            'flags': list(flags), 'command': ['gcc'], 'hardening': {**evidence(name), 'raw': f'{name}.txt'}}


HARDENED = {'nx': 'enabled', 'pie': 'enabled', 'relro': 'full', 'stack_canary': 'present', 'fortify_source': 'present'}


class InterpretTests(unittest.TestCase):
    def test_each_recorded_variant(self):
        expected = {
            'hardened': HARDENED,
            'execstack': {**HARDENED, 'nx': 'disabled'},
            'no-pie': {**HARDENED, 'pie': 'disabled'},
            'partial-relro': {**HARDENED, 'relro': 'partial'},
            'no-relro': {**HARDENED, 'relro': 'none'},
            'no-canary': {**HARDENED, 'stack_canary': 'not-observed'},
            'no-fortify': {**HARDENED, 'fortify_source': 'not-observed'},
        }
        for name, protections in expected.items():
            with self.subTest(sample=name):
                self.assertEqual(interpret(evidence(name)), protections)

    def test_fortify_symbols_exclude_the_stack_protector(self):
        self.assertEqual(evidence('hardened')['fortify_symbols'], ['__fprintf_chk', '__memcpy_chk', '__printf_chk'])

    def test_failed_extraction_is_unknown(self):
        self.assertEqual(set(interpret({'extraction_complete': False}).values()), {'unknown'})

    def test_instrumentation_markers_detect_sanitizer_runtime(self):
        symbols = '    __asan_init\n    __ubsan_handle_type_mismatch\n    main\n'
        markers = instrumentation_markers(symbols)
        self.assertTrue(markers['asan'])
        self.assertTrue(markers['ubsan'])
        self.assertIn('__asan_init', markers['symbols'])
        self.assertFalse(instrumentation_markers('    main\n')['asan'])
        self.assertFalse(instrumentation_markers('    main\n')['ubsan'])


def markers(asan=False, ubsan=False, tsan=False, msan=False, symbols=()):
    return {'asan': asan, 'ubsan': ubsan, 'tsan': tsan, 'msan': msan,
            'symbols': sorted(set(symbols))}


class InstrumentationValidationTests(unittest.TestCase):
    """Review item 2: release/sanitized instrumentation must match the declared type."""

    def test_normal_release_is_accepted(self):
        validate_instrumentation('release', markers(), {})  # no exception

    def test_release_with_sanitizer_marker_is_config_error(self):
        with self.assertRaises(ConfigError):
            validate_instrumentation('release', markers(asan=True, symbols=['__asan_init']), {})

    def test_sanitized_with_declared_marker_is_accepted(self):
        validate_instrumentation('sanitized', markers(asan=True, symbols=['__asan_init']),
                                 {'instrumentation': ['__asan_init']})

    def test_sanitized_without_declared_marker_is_config_error(self):
        with self.assertRaises(ConfigError):
            validate_instrumentation('sanitized', markers(), {'instrumentation': ['__asan_init']})

    def test_sanitized_with_any_runtime_and_no_declaration_is_accepted(self):
        validate_instrumentation('sanitized', markers(ubsan=True, symbols=['__ubsan_handle_type_mismatch']), {})


class CompareTests(unittest.TestCase):
    def test_same_protections(self):
        result = compare_hardening(build('base', 'hardened'), build('candidate', 'hardened'))
        self.assertEqual(result['interpretation'], 'complete')
        self.assertEqual((result['degraded'], result['warnings']), ([], []))
        self.assertEqual(set(result['changes'].values()), {'same'})

    def test_nx_pie_relro_loss_is_degradation(self):
        for name, protection in (('execstack', 'nx'), ('no-pie', 'pie'), ('partial-relro', 'relro'),
                                 ('no-relro', 'relro')):
            with self.subTest(sample=name):
                result = compare_hardening(build('base', 'hardened'), build('candidate', name))
                self.assertEqual(result['changes'][protection], 'degraded')
                self.assertEqual(len(result['degraded']), 1)

    def test_gain_is_improvement(self):
        result = compare_hardening(build('base', 'no-relro'), build('candidate', 'partial-relro'))
        self.assertEqual(result['changes']['relro'], 'improved')
        self.assertEqual(result['degraded'], [])

    def test_lost_canary_or_fortify_symbols_only_warn(self):
        for name in ('no-canary', 'no-fortify'):
            with self.subTest(sample=name):
                result = compare_hardening(build('base', 'hardened'), build('candidate', name))
                self.assertEqual(result['degraded'], [])
                self.assertEqual(len(result['warnings']), 1)
                self.assertIn('absence is not proof', result['warnings'][0])

    def test_changed_build_flags_are_reported(self):
        result = compare_hardening(build('base', 'hardened'), build('candidate', 'hardened', flags=('-O0',)))
        self.assertFalse(result['flags_equal'])
        self.assertIn('flags', result['warnings'][0])

    def test_missing_release_build_is_unknown(self):
        self.assertEqual(compare_hardening(build('base', 'hardened'), None)['interpretation'], 'unknown')


class VerdictTests(unittest.TestCase):
    """A fixed, regression-free patch that weakens a protection cannot PASS."""

    def report(self, candidate_sample):
        crash = {'error_type': 'heap-buffer-overflow', 'detection_method': 'asan', 'confirmation': 'confirmed',
                 'signature': {'error_type': 'heap-buffer-overflow', 'location': 'p.c:copy', 'key': 'WRITE'},
                 'complete_evidence': True, 'location': None, 'access': None}
        tests = [{'id': 'poc', 'category': 'original', 'signature': crash['signature'], 'regression': None},
                 {'id': 'valid', 'category': 'valid', 'signature': None, 'regression': None},
                 {'id': 'boundary', 'category': 'boundary', 'signature': None, 'regression': None},
                 {'id': 'invalid', 'category': 'invalid', 'signature': None, 'regression': None}]
        runs = []
        for version in ('base', 'candidate'):
            for build_type in ('release', 'sanitized'):
                for test in tests:
                    obs = [crash] if test['id'] == 'poc' and version == 'base' else []
                    runs.append({'id': f'{test["id"]}-{version}-{build_type}', 'test_id': test['id'],
                                 'version': version, 'build_type': build_type, 'replay_of': None,
                                 'oracle': {'status': 'fail' if test['id'] == 'poc' and version == 'base' else 'pass'},
                                 'stdout': 'o', 'stderr': 'e',
                                 'analysis': {'observations': obs}, 'signal': None, 'resource_status': 'ok'})
        return compare_report({'tests': tests, 'runs': runs, 'diff': {}, 'technical_errors': [], 'replays': [],
                               'unstable': [], 'fixture': False,
                               'builds': [build('base', 'hardened'), build('candidate', candidate_sample)]})

    def test_hardened_fix_passes_and_degraded_fix_is_inconclusive(self):
        self.assertEqual(self.report('hardened')['exit_code'], 0)
        report = self.report('execstack')
        self.assertEqual(report['exit_code'], 40)
        self.assertIn('hardening-degraded: nx: enabled -> disabled', report['axes']['completeness']['reasons'])
        self.assertEqual(decide({'baseline_reproduced': True, 'hardening_degraded': True}), 40)

    def test_symbol_only_loss_does_not_block_pass(self):
        self.assertEqual(self.report('no-canary')['exit_code'], 0)


if __name__ == '__main__':
    unittest.main()
