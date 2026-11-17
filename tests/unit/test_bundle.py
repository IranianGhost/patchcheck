import unittest

from patchcheck.bundle import bundle_test_ids, verify_rebuilt_binaries
from patchcheck.contracts import ConfigError


class BundleTests(unittest.TestCase):
    def test_all_confirmed_cases_are_selected_including_functional_regressions(self):
        report = {'tests': [{'id': 'valid', 'signature': None}, {'id': 'other', 'signature': None}],
                  'runs': [{'id': 'base', 'test_id': 'other'}],
                  'findings': [{'confirmation': 'confirmed', 'base_run_ids': ['base'], 'candidate_run_ids': []}]}
        self.assertEqual(bundle_test_ids(report), {'other'})

    def test_rebuilt_binary_and_its_build_command_must_match(self):
        original = {'builds': [{'id': 'base-release', 'binary_sha256': 'a',
                                'command': ['gcc'], 'flags': ['-O2']}]}
        verify_rebuilt_binaries(original, original)
        for field, changed in [('binary_sha256', 'b'), ('command', ['clang']), ('flags', ['-O0'])]:
            with self.subTest(field=field), self.assertRaises(ConfigError):
                verify_rebuilt_binaries(original, {'builds': [{**original['builds'][0], field: changed}]})
