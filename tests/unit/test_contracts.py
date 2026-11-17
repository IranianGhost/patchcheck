import json
import os
import tempfile
import unittest
from pathlib import Path

from _tmp import tmpdir
from patchcheck.contracts import ConfigError, validate
from patchcheck.store import checked_path, digest, read_json, write_json

POSIX = os.name == 'posix'


class ContractTests(unittest.TestCase):
    def minimal_config(self, tmp):
        """A schema-valid config pointing at a real temp repo and one real input."""
        (tmp / 'input.bin').write_bytes(b'x')
        return {
            'schema_version': '1.0', 'target': 't', 'fixture': False,
            'source': {'repo': str(tmp), 'base': 'base', 'candidate': 'candidate'},
            'builds': {
                'release': {'command': ['{compiler}', '{flags}', 'x.c', '-o', 'x'], 'binary': 'x',
                            'compiler': 'gcc', 'flags': []},
                'sanitized': {'command': ['{compiler}', '{flags}', 'x.c', '-o', 'x'], 'binary': 'x',
                              'compiler': 'gcc', 'flags': ['-fsanitize=address'],
                              'instrumentation': ['__asan_init']},
            },
            'input': {'mode': 'stdin', 'argv': ['{binary}'], 'cwd': '.'},
            'environment': {'image': 'img', 'variables': {}},
            'tools': {'gcc': 'gcc', 'git': 'git', 'python3': 'py', 'readelf': 're'},
            'limits': {'wall_seconds': 3, 'cpu_seconds': 2, 'memory_mb': 384, 'pids': 32,
                       'output_bytes': 1024, 'file_bytes': 1024, 'build_wall_seconds': 60},
            'tests': [{'id': 't1', 'category': 'valid', 'input': str(tmp / 'input.bin'),
                       'oracle': None, 'signature': None}],
            'corpus_dir': str(tmp), 'analyzers': [], 'minimization': {'max_attempts': 10, 'wall_seconds': 10},
        }

    def test_missing_readelf_is_rejected_as_configuration(self):
        with tmpdir() as tmp:
            config = self.minimal_config(Path(tmp))
            config['tools'].pop('readelf')
            write_json(Path(tmp) / 'config.json', config)
            with self.assertRaises(ConfigError) as ctx:
                from patchcheck.contracts import load_config
                load_config(Path(tmp) / 'config.json')
            self.assertIn('readelf', str(ctx.exception))

    def test_identical_release_and_sanitized_specs_are_rejected(self):
        with tmpdir() as tmp:
            config = self.minimal_config(Path(tmp))
            config['builds']['sanitized'] = dict(config['builds']['release'])
            write_json(Path(tmp) / 'config.json', config)
            with self.assertRaises(ConfigError) as ctx:
                from patchcheck.contracts import load_config
                load_config(Path(tmp) / 'config.json')
            self.assertIn('must differ', str(ctx.exception))

    def test_coverage_evidence_reference_is_validated(self):
        from patchcheck.report import verify_references
        report = {'config': 'config.json', 'diff': {'coverage': {'runs': [{'evidence': ['coverage/x.gcov']}]}},
                  'builds': [], 'tests': [], 'runs': [], 'findings': []}
        with tmpdir() as tmp:
            root = Path(tmp)
            (root / 'config.json').write_text('{}')
            with self.assertRaises(ConfigError):
                verify_references(report, root)
            (root / 'coverage').mkdir()
            (root / 'coverage/x.gcov').write_text('')
            verify_references(report, root)  # no error now

    def test_coverage_evidence_must_have_a_matching_hash_entry(self):
        from patchcheck.report import verify_coverage_evidence
        from patchcheck.store import digest
        with tmpdir() as tmp:
            root = Path(tmp)
            (root / 'cov').mkdir()
            (root / 'cov' / 'x.gcov').write_text('line')
            report = {'evidence_index': {'cov/x.gcov': digest(root / 'cov' / 'x.gcov')},
                      'diff': {'coverage': {'runs': [{'evidence': ['cov/x.gcov']}]}}}
            verify_coverage_evidence(report, root)  # ok
            # Remove the hash entry -> rejected.
            report['evidence_index'] = {}
            with self.assertRaises(ConfigError):
                verify_coverage_evidence(report, root)
            # Wrong hash -> rejected.
            report['evidence_index'] = {'cov/x.gcov': '0' * 64}
            with self.assertRaises(ConfigError):
                verify_coverage_evidence(report, root)
            # Missing file -> rejected.
            report['evidence_index'] = {'cov/x.gcov': digest(root / 'cov' / 'x.gcov')}
            report['diff']['coverage']['runs'][0]['evidence'] = ['cov/missing.gcov']
            with self.assertRaises(ConfigError):
                verify_coverage_evidence(report, root)

    def test_report_test_ids_cannot_escape_artifact_paths(self):
        test = {'schema_version':'1.0','id':'../../escape','target':'fixture','category':'valid',
                'input':'input.bin','sha256':'0'*64,'size':0,'input_mode':'stdin',
                'oracle':None,'signature':None,'origin':'test','regression':None}
        for value in ('../../escape','/absolute','a/b','..'):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                validate('TestCase', {**test, 'id': value})

    def test_missing_and_wrong_contract_fields_are_rejected(self):
        for kind in ['TargetConfig', 'TestCase', 'BuildRecord', 'RunRecord', 'Finding', 'PatchRelation', 'FinalReport']:
            with self.subTest(kind=kind), self.assertRaises(ConfigError):
                validate(kind, {'schema_version': '1.0'})

    def test_schema_rejects_invalid_enum_and_unknown_version(self):
        with self.assertRaises(ConfigError):
            validate('Oracle', {'schema_version': '99'})
        with self.assertRaises(ConfigError):
            validate('RunRecord', {'schema_version': '1.0', 'signal': 'SIGSEGV'})

    def test_runtime_oracle_and_completeness_fields_are_not_untyped_objects(self):
        from importlib.resources import files
        from jsonschema import Draft202012Validator
        schema = json.loads(files('patchcheck').joinpath('schemas/RunRecord.schema.json').read_text())
        definitions = schema['$defs']
        oracle_schema = {**definitions['RunRecord']['properties']['oracle'], '$defs': definitions}
        self.assertTrue(list(Draft202012Validator(oracle_schema).iter_errors({'status': 'invented'})))

    def test_atomic_evidence_is_binary_safe_and_confined(self):
        with tmpdir() as tmp:
            root = tmp
            path = root / 'd' / 'record.json'
            write_json(path, {'test': '\u0633\u0644\u0627\u0645'})
            self.assertEqual(read_json(path), {'test': '\u0633\u0644\u0627\u0645'})
            (root / 'binary').write_bytes(b'\x00\xff')
            self.assertEqual(digest(root / 'binary'), '06eb7d6a69ee19e5fbdf749018d3d2abfa04bcbd1365db312eb86dc7169389b8')
            with self.assertRaises(ConfigError):
                checked_path(root, '../outside')

    @unittest.skipUnless(POSIX, 'requires POSIX symlink support')
    def test_symlink_escape_is_confined(self):
        with tmpdir() as tmp:
            root = tmp
            (root / 'escape').symlink_to('/tmp')
            with self.assertRaises(ConfigError):
                checked_path(root, 'escape/outside')
