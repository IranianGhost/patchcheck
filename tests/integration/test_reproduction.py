import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from patchcheck.bundle import make_bundle, reproduce, unpack_bundle
from patchcheck.contracts import ConfigError
from patchcheck.minimize import minimize_case
from patchcheck.pipeline import run_pipeline
from patchcheck.replay import replay_case
from patchcheck.report import load_report

ROOT = Path(__file__).resolve().parents[2]


class BundleSafetyTests(unittest.TestCase):
    def test_archive_traversal_and_links_are_rejected_before_extracting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, kind in [('../escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)]:
                archive = root / 'bad.tar.gz'
                with tarfile.open(archive, 'w:gz') as stream:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = '/etc/passwd'
                    item.size = 0
                    stream.addfile(item, io.BytesIO(b''))
                with self.assertRaises(ConfigError):
                    unpack_bundle(archive, root / 'unpacked')
                self.assertFalse((root / 'escape').exists())


@unittest.skipUnless(os.environ.get('PATCHCHECK_INTEGRATION') == '1', 'real Docker integration opt-in')
class ReproductionTests(unittest.TestCase):
    def test_minimized_regression_reloads_and_bundle_rebuilds_portably(self):
        import json
        from patchcheck.contracts import load_config
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(ROOT / 'configs/bytecount-stdin.json')
            config['source']['repo'] = str(ROOT / '.fixture-repos/bytecount')
            config['corpus_dir'] = str(root / 'corpus')
            for test in config['tests']:
                for field in ('input', 'oracle'):
                    test[field] = str((ROOT / 'configs' / test[field]).resolve())
            path = root / 'config.json'
            path.write_text(json.dumps(config))
            report = run_pipeline(path, root / 'first')
            replay = replay_case(root / 'first/report.json', 'marker', 3)
            self.assertEqual(replay['status'], 'stable')
            self.assertEqual(len(replay['run_ids']), 12)
            result = minimize_case(root / 'first/report.json', 'marker')
            self.assertTrue(result['registered'])
            finalized = load_report(root / 'first/report.json')
            matching_scope = [entry for entry in finalized['minimization_scope']
                              if entry['minimized_test_id'] == result['minimized_test_id']]
            self.assertTrue(matching_scope)
            for entry in matching_scope:
                self.assertTrue(entry['registered'])
                row = next(line for line in (root / 'first/summary.md').read_text().splitlines()
                           if line.startswith(f'| {entry["finding_id"]} | {entry["status"]} |'))
                self.assertEqual(row.split('|')[4].strip(), 'yes')
            self.assertEqual((root / 'first' / result['minimized']).read_bytes(), b'MARK')
            second = run_pipeline(path, root / 'second')
            generated = [test for test in second['tests'] if test['origin'] == 'generated-regression']
            self.assertEqual(len(generated), 1)
            comparisons = [pair for pair in second['axes']['functional']['comparisons'] if 'generated_regression' in pair]
            self.assertEqual(len(comparisons), 2)
            self.assertTrue(all(pair['generated_regression']['status'] == 'pass' for pair in comparisons))
            archive = make_bundle(root / 'first/report.json', root / 'bundle.tar.gz', include_image=False)
            unpack_bundle(archive, root / 'portable-cli')
            import subprocess
            import sys
            environment = {**os.environ, 'PYTHONPATH': str(root / 'portable-cli/project/src')}
            result = subprocess.run([sys.executable, '-m', 'patchcheck', 'reproduce', str(archive), '--out', str(root / 'clean-reproduction')],
                                    cwd=root, env=environment, capture_output=True)
            self.assertEqual(result.returncode, 40, result.stderr.decode(errors='replace'))
            rebuilt = load_report(root / 'clean-reproduction/result/report.json')
            self.assertEqual(rebuilt['exit_code'], 40)
            self.assertEqual(len(rebuilt['builds']), 4)
            self.assertTrue(rebuilt['replays'])
            self.assertTrue(all(b['result'] == 'success' for b in rebuilt['builds']))
