import json
import os
import tempfile
import unittest
from pathlib import Path

from patchcheck.contracts import ConfigError, load_config, validate
from patchcheck.pipeline import run_pipeline
from patchcheck.report import load_report

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('PATCHCHECK_INTEGRATION') == '1', 'real Docker integration opt-in')
class PipelineTests(unittest.TestCase):
    def test_new_candidate_ref_real_regression_both_wrong_and_missing_oracle(self):
        import subprocess
        from patchcheck.source import git
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'new-source'
            subprocess.run(['git', 'clone', '-q', str(ROOT / '.fixture-repos/bytecount'), str(repo)], check=True)
            git(repo, 'config', 'user.name', 'Framework test')
            git(repo, 'config', 'user.email', 'test@example.invalid')
            source = repo / 'main.c'
            source.write_text(source.read_text().replace('fputs("OK\\n", stdout)', 'fputs("WRONG\\n", stdout)'))
            git(repo, 'add', 'main.c')
            git(repo, 'commit', '-qm', 'new candidate with harmless output regression')
            git(repo, 'tag', 'new-candidate')
            config = load_config(ROOT / 'configs/bytecount-stdin.json')
            config['source'] = {'repo': str(repo), 'base': 'base', 'candidate': 'new-candidate'}
            config['corpus_dir'] = str(root / 'regressions')
            for test in config['tests']:
                test['input'] = str((ROOT / 'configs' / test['input']).resolve())
                test['oracle'] = None if test['id'] == 'empty' else str((ROOT / 'configs' / test['oracle']).resolve())
            path = root / 'new-config.json'
            path.write_text(json.dumps(config))
            report = run_pipeline(path, root / 'result')
            # A real oracle-confirmed regression outranks INCONCLUSIVE, even on a fixture.
            self.assertEqual(report['exit_code'], 20)
            self.assertEqual(report['axes']['functional']['decision_engine_code'], 20)
            self.assertIn('fixture-target: fixture evidence never validates a real patch',
                          report['axes']['completeness']['reasons'])
            states = {pair['test_id']: pair['status'] for pair in report['axes']['functional']['comparisons']}
            self.assertEqual(states, {'binary': 'regression', 'empty': 'unknown', 'invalid': 'preserved', 'marker': 'both_fail'})
            self.assertTrue(report['diff']['hunks'])
            self.assertTrue(all(b['result'] == 'success' for b in report['builds']))

    def test_three_input_modes_four_build_cells_and_independent_oracles(self):
        for name in ('bytecount-stdin', 'bytecount-file', 'lineparse-argv'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                report = run_pipeline(ROOT / 'configs' / (name + '.json'), Path(tmp) / 'run')
                self.assertEqual(report['exit_code'], 40)
                self.assertEqual(len(report['builds']), 4)
                self.assertEqual(len(report['runs']), 16)
                self.assertEqual({b['architecture'] for b in report['builds']}, {'x86_64'})
                self.assertEqual({b['build_type'] for b in report['builds']}, {'release', 'sanitized'})
                for run in report['runs']:
                    self.assertIsNone(run['runner_error'])
                    if run['test_id'] == 'invalid':
                        self.assertEqual(run['exit_code'], 2)
                        self.assertEqual(run['oracle']['status'], 'pass')
                loaded = load_report(Path(tmp) / 'run' / 'report.json')
                self.assertEqual(loaded['id'], report['id'])
                self.assertFalse(report['axes']['completeness']['complete'])
                self.assertEqual(report['hardening']['interpretation'], 'complete')
                self.assertEqual(report['hardening']['degraded'], [])
                self.assertTrue(all(b['hardening']['extraction_complete'] for b in report['builds']))
                # Corrupting a referenced evidence file must fail rather than PASS.
                (Path(tmp) / 'run' / report['runs'][0]['stdout']).unlink()
                with self.assertRaises(ConfigError):
                    load_report(Path(tmp) / 'run' / 'report.json')

    def test_real_build_failure_produces_report_30(self):
        config = load_config(ROOT / 'configs/bytecount-stdin.json')
        with tempfile.TemporaryDirectory() as tmp:
            # Make all external paths explicit for the temporary config root.
            config['source']['repo'] = str(ROOT / '.fixture-repos/bytecount')
            config['corpus_dir'] = str(Path(tmp) / 'regressions')
            for test in config['tests']:
                for field in ('input', 'oracle'):
                    test[field] = str((ROOT / 'configs' / test[field]).resolve())
            config['builds']['release']['flags'].append('-this-flag-does-not-exist')
            path = Path(tmp) / 'bad.json'
            path.write_text(json.dumps(config))
            report = run_pipeline(path, Path(tmp) / 'run')
            self.assertEqual(report['exit_code'], 30)
            self.assertTrue(report['technical_errors'])
            validate('FinalReport', report)
