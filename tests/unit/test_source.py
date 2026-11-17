import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from patchcheck.contracts import ConfigError
from patchcheck.source import snapshot_versions

POSIX = os.name == 'posix'


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


class SourceTests(unittest.TestCase):
    @unittest.skipUnless(POSIX, 'requires a POSIX host (git bundle, byte-exact files)')
    def test_dirty_untracked_binary_sources_are_reproducible_and_diff_is_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            git(repo, 'init', '-q')
            git(repo, 'config', 'user.name', 'Fixture')
            git(repo, 'config', 'user.email', 'fixture@example.invalid')
            (repo / 'main.c').write_text('int main(){return 0;}\n')
            (repo / '.gitignore').write_text('ignored.bin\n')
            (repo / '.gitattributes').write_text('*.c text eol=lf\nsecret.bin export-ignore\n')
            (repo / 'secret.bin').write_bytes(b'tracked\0\xff')
            git(repo, 'add', '.')
            git(repo, 'commit', '-qm', 'base')
            git(repo, 'tag', 'base')
            (repo / 'main.c').write_text('int main(){return 1;}\n')
            git(repo, 'commit', '-qam', 'candidate')
            git(repo, 'tag', 'candidate')
            (repo / 'untracked.bin').write_bytes(b'\0\xff\x80')
            (repo / 'main.c').write_bytes(b'int main(){return 2;}\r\n')
            (repo / 'ignored.bin').write_bytes(b'\0ignored\xff')
            config = {'source': {'repo': str(repo), 'base': 'base', 'candidate': 'candidate',
                                 'dirty': {'version': 'candidate', 'path': str(repo)}}}
            result = snapshot_versions(config, root / 'out', root)
            candidate = root / 'out' / result['candidate']['path']
            self.assertEqual((candidate / 'secret.bin').read_bytes(), b'tracked\0\xff')
            self.assertEqual((candidate / 'untracked.bin').read_bytes(), b'\0\xff\x80')
            self.assertIn('return 2', (candidate / 'main.c').read_text())
            self.assertTrue(result['candidate']['dirty'])
            self.assertTrue(result['diff']['hunks'])
            clone = root / 'clone'
            subprocess.run(['git', 'clone', '-q', str(root / 'out/sources/snapshots.bundle'), str(clone)], check=True)
            self.assertEqual(git(clone, 'show', 'candidate:main.c'), b'int main(){return 2;}\r\n')
            self.assertEqual(git(clone, 'show', 'candidate:ignored.bin'), b'\0ignored\xff')
            config['source']['diff'] = str(root / 'wrong.diff')
            (root / 'wrong.diff').write_text('not a patch\n')
            with self.assertRaises(ConfigError):
                snapshot_versions(config, root / 'other', root)

    @unittest.skipUnless(POSIX, 'requires POSIX symlink support')
    def test_source_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            git(repo, 'init', '-q')
            git(repo, 'config', 'user.name', 'Fixture')
            git(repo, 'config', 'user.email', 'fixture@example.invalid')
            (repo / 'escape').symlink_to('/etc/passwd')
            git(repo, 'add', '.')
            git(repo, 'commit', '-qm', 'unsafe')
            with self.assertRaises(ConfigError):
                snapshot_versions({'source': {'repo': str(repo), 'base': 'HEAD', 'candidate': 'HEAD'}}, root / 'out', root)

    def test_deleted_hunks_keep_the_deleted_filename(self):
        from patchcheck.source import parse_hunks
        diff = b'diff --git a/gone.c b/gone.c\n--- a/gone.c\n+++ /dev/null\n@@ -1 +0,0 @@\n-deleted\n'
        self.assertEqual(parse_hunks(diff)[0]['file'], 'gone.c')

    def test_git_quoted_filename_round_trips_in_hunks(self):
        from patchcheck.source import parse_hunks
        diff = b'diff --git "a/space\\tname.c" "b/space\\tname.c"\n--- "a/space\\tname.c"\n+++ "b/space\\tname.c"\n@@ -1 +1 @@\n-old\n+new\n'
        self.assertEqual(parse_hunks(diff)[0]['file'], 'space\tname.c')

    @unittest.skipUnless(POSIX, 'requires a POSIX host (git apply)')
    def test_apply_patch_tree_materializes_base_plus_unseen_diff(self):
        from patchcheck.source import apply_patch_tree
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / 'base'
            (base / 'lib').mkdir(parents=True)
            (base / 'lib' / 'x.c').write_text('int f(void){return 0;}\n')
            # A standard `git diff` style patch with a/,b/ prefixes.
            patch = root / 'p.diff'
            patch.write_bytes(b'diff --git a/lib/x.c b/lib/x.c\n--- a/lib/x.c\n+++ b/lib/x.c\n'
                              b'@@ -1 +1 @@\n-int f(void){return 0;}\n+int f(void){return 1;}\n')
            dest = root / 'candidate'
            apply_patch_tree(base, patch, dest)
            self.assertEqual((dest / 'lib' / 'x.c').read_text(), 'int f(void){return 1;}\n')

    @unittest.skipUnless(POSIX, 'requires a POSIX host (git apply)')
    def test_apply_patch_tree_rejects_a_patch_that_does_not_apply(self):
        from patchcheck.source import apply_patch_tree
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / 'base'
            base.mkdir()
            (base / 'x.c').write_text('original\n')
            patch = root / 'p.diff'
            patch.write_bytes(b'--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-something else\n+changed\n')
            with self.assertRaises(ConfigError):
                apply_patch_tree(base, patch, root / 'candidate')
