import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _tmp import tmpdir
from patchcheck.contracts import ConfigError
from patchcheck.store import write_json

ROOT = Path(__file__).resolve().parents[2]


class CliTests(unittest.TestCase):
    def test_malformed_configuration_has_clear_technical_exit_code(self):
        with tmpdir() as tmp:
            path = Path(tmp) / 'invalid.json'
            path.write_text('{"schema_version":"wrong"}')
            result = subprocess.run([sys.executable, '-m', 'patchcheck', 'validate-config', str(path)], capture_output=True)
            self.assertEqual(result.returncode, 30)
            self.assertIn(b'BUILD_OR_CONFIG_ERROR', result.stderr)
            self.assertIn(b'TargetConfig', result.stderr)

    def test_serialization_failure_is_technical_and_leaves_no_partial_report(self):
        with tmpdir() as tmp:
            path = Path(tmp) / 'report.json'
            with self.assertRaises(ConfigError):
                write_json(path, {'unsupported': object()})
            self.assertFalse(path.exists())

    def test_reading_missing_report_is_technical(self):
        result = subprocess.run([sys.executable, '-m', 'patchcheck', 'report', '/does-not-exist/report.json'], capture_output=True)
        self.assertEqual(result.returncode, 30)

    @unittest.skipUnless((ROOT / '.fixture-repos/tlvparse').is_dir(), 'run tools/setup_fixtures.py first')
    def test_candidate_override_is_recorded_and_unknown_ref_is_technical(self):
        with tmpdir() as tmp:
            out = Path(tmp) / 'out'
            result = subprocess.run([sys.executable, '-m', 'patchcheck', 'run', str(ROOT / 'configs/tlvparse-file.json'),
                                     '--candidate', 'no-such-patch', '--out', str(out)], capture_output=True)
            self.assertEqual(result.returncode, 30)
            self.assertEqual(json.loads((out / 'config.json').read_text())['source']['candidate'], 'no-such-patch')
            self.assertIn('no-such-patch', ' '.join(json.loads((out / 'report.json').read_text())['technical_errors']))

    @unittest.skipUnless((ROOT / '.fixture-repos/giflib').is_dir(), 'run tools/setup_fixtures.py first')
    def test_patch_with_candidate_is_rejected_as_technical(self):
        with tmpdir() as tmp:
            out = Path(tmp) / 'out'
            patch = Path(tmp) / 'p.diff'
            patch.write_text('--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n')
            result = subprocess.run([sys.executable, '-m', 'patchcheck', 'run', str(ROOT / 'configs/giflib-file.json'),
                                     '--patch', str(patch), '--candidate', 'correct', '--out', str(out)],
                                    capture_output=True)
            self.assertEqual(result.returncode, 30)
            report = json.loads((out / 'report.json').read_text())
            self.assertIn('--patch cannot be combined', ' '.join(report['technical_errors']))

    def test_invalid_bundle_is_technical_without_uncaught_traceback(self):
        with tmpdir() as tmp:
            archive = Path(tmp) / 'bad.tar.gz'
            archive.write_bytes(b'not a gzip archive')
            result = subprocess.run([sys.executable, '-m', 'patchcheck', 'reproduce', str(archive), '--out', str(Path(tmp) / 'out')], capture_output=True)
            self.assertEqual(result.returncode, 30)
            self.assertNotIn(b'Traceback', result.stderr)

