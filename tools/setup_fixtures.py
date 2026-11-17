"""Create deterministic Git repositories for every target under targets/.

Layout: targets/<name>/<version>/ holds the full source tree of one version.
`base` is committed first; every other version is committed as a direct child
of `base` and tagged with its folder name, so `git diff base <version>` is
exactly that patch. Result: .fixture-repos/<name> with one tag per version.

Existing repositories are verified, never overwritten; missing version tags are
added. Pass --rebuild to delete and recreate repositories whose sources changed.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOS = ROOT / '.fixture-repos'
ENV = {**os.environ, 'GIT_AUTHOR_DATE': '2026-11-10T00:00:00+00:00',
       'GIT_COMMITTER_DATE': '2026-11-10T00:00:00+00:00'}


def git(repo, *args, capture=False):
    result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args], check=True,
                            env=ENV, stdout=subprocess.PIPE if capture else subprocess.DEVNULL)
    return result.stdout.decode().strip() if capture else None


def tracked_files(folder):
    return {p.relative_to(folder).as_posix(): p.read_bytes()
            for p in sorted(folder.rglob('*')) if p.is_file() and p.name != '.DS_Store'}


def tag_files(repo, tag):
    names = git(repo, 'ls-tree', '-r', '--name-only', tag, capture=True).splitlines()
    return {n: subprocess.check_output(['git', '-C', str(repo), 'show', f'{tag}:{n}']) for n in names}


def commit_version(repo, version, files):
    git(repo, 'checkout', '-q', '--detach', 'base') if version != 'base' else None
    for path in repo.iterdir():
        if path.name != '.git':
            shutil.rmtree(path) if path.is_dir() else path.unlink()
    for rel, data in files.items():
        dest = repo / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    git(repo, 'add', '-A')
    git(repo, 'commit', '-q', '--allow-empty', '-m', version)
    git(repo, 'tag', version)


def setup_target(target, rebuild):
    versions = sorted(p.name for p in target.iterdir() if p.is_dir())
    if 'base' not in versions:
        raise RuntimeError(f'{target} has no base/ version')
    versions.remove('base')
    sources = {v: tracked_files(target / v) for v in ['base', *versions]}
    repo = REPOS / target.name
    if repo.exists():
        existing = set(git(repo, 'tag', '--list', capture=True).splitlines())
        stale = [v for v in sources if v in existing and tag_files(repo, v) != sources[v]]
        if stale and not rebuild:
            raise RuntimeError(f'{repo}: sources changed for {stale}; rerun with --rebuild')
        if stale:
            shutil.rmtree(repo)
    if not repo.exists():
        repo.mkdir(parents=True)
        git(repo, 'init', '-q')
        git(repo, 'config', 'user.name', 'Patchcheck fixture')
        git(repo, 'config', 'user.email', 'fixture@example.invalid')
    existing = set(git(repo, 'tag', '--list', capture=True).splitlines())
    for version in ['base', *versions]:
        if version not in existing:
            commit_version(repo, version, sources[version])
    print(f'{target.name}: {", ".join(["base", *versions])}')


def setup(rebuild=False):
    for target in sorted((ROOT / 'targets').iterdir()):
        if target.is_dir():
            setup_target(target, rebuild)
    print('Fixture Git revisions ready in .fixture-repos/')


if __name__ == '__main__':
    setup(rebuild='--rebuild' in sys.argv[1:])
