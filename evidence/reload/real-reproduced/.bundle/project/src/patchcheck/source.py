"""Snapshot exact Git revisions/dirty sources without mutating the input repository."""
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .contracts import ConfigError
from .sourcemap import annotate
from .store import bytes_digest, digest, write_json


def git(repo, *args, ok=(0,), env=None, input=None):
    try:
        process = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args],
                                 input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                 env={**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
                                      **(env or {})})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigError(f'Git environment failure: {exc}') from exc
    if process.returncode not in ok:
        raise ConfigError(f'git {args[0]} failed: {process.stderr.decode(errors="replace")}')
    return process.stdout


def safe_extract(archive, destination):
    destination = Path(destination).resolve()
    for member in archive.getmembers():
        path = (destination / member.name).resolve()
        if not path.is_relative_to(destination) or not (member.isfile() or member.isdir()):
            raise ConfigError(f'unsafe archive member: {member.name}')
    archive.extractall(destination, members=archive.getmembers())


def tree_hashes(path):
    result = {}
    for item in sorted(Path(path).rglob('*')):
        if '.git' in item.relative_to(path).parts:
            continue
        if item.is_symlink() or (not item.is_file() and not item.is_dir()):
            raise ConfigError(f'unsupported source symlink/special file: {item}')
        if item.is_file():
            result[str(item.relative_to(path))] = {'sha256': digest(item), 'executable': bool(item.stat().st_mode & 0o111)}
    return result


def export_tree(repo, commit, destination):
    """Read raw committed blobs; git archive can apply export attributes."""
    destination = Path(destination).resolve()
    for entry in git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not entry:
            continue
        header, raw_name = entry.split(b'\t', 1)
        mode, kind, oid = header.split()
        if kind != b'blob' or mode not in (b'100644', b'100755'):
            raise ConfigError(f'unsupported source symlink/submodule/special entry: {raw_name!r}')
        path = (destination / os.fsdecode(raw_name)).resolve()
        if not path.is_relative_to(destination):
            raise ConfigError('Git tree path escapes snapshot destination')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(git(repo, 'cat-file', 'blob', oid.decode('ascii')))
        path.chmod(0o755 if mode == b'100755' else 0o644)


def copy_source(source, dest):
    tree_hashes(source)  # Reject escapes before copying.
    if Path(dest).resolve().is_relative_to(Path(source).resolve()):
        raise ConfigError('source destination must not be inside the source tree')
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns('.git'), dirs_exist_ok=True)


def apply_patch_tree(base_tree, patch_path, dest):
    """Materialize `dest` = `base_tree` with the unified diff at `patch_path` applied.

    Used for the defense-day `--patch` flow, where the candidate is not a known Git
    ref but an unseen diff handed over as a file. The patch is applied inside a
    throwaway Git repository so git refuses paths that escape the source tree; the
    standard `a/`,`b/` prefix (`-p1`) is tried first, then `-p0`.
    """
    patch_path = Path(patch_path)
    if not patch_path.is_file():
        raise ConfigError(f'patch file not found: {patch_path}')
    with tempfile.TemporaryDirectory(prefix='patchcheck-patch-') as tmp:
        tmp = Path(tmp)
        git(tmp, 'init', '-q')
        copy_source(base_tree, tmp)
        # Apply inside the repo so git refuses paths that escape the tree. Try the
        # standard a/,b/ prefix first, then a prefixless diff; stop at the first hit.
        errors = []
        for strip in (['-p1'], ['-p0']):
            result = subprocess.run(['git', '-C', str(tmp), 'apply', *strip, '--', str(patch_path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                break
            errors.append(f'{strip[0]}: {result.stderr.decode(errors="replace").strip()}')
        else:
            raise ConfigError(f'could not apply patch {patch_path.name} to base ({"; ".join(errors)})')
        copy_source(tmp, dest)


def parse_hunks(raw):
    hunks, filename, old_filename = [], None, None
    def parse_path(value):
        if value == '/dev/null':
            return None
        if value.startswith('"'):
            # Git's C quoting encodes non-ASCII bytes as octal, which JSON's
            # string parser does not support. Decode quoted bytes explicitly.
            body = value[1:-1]
            table = {'t': b'\t', 'n': b'\n', 'r': b'\r', 'b': b'\b', 'f': b'\f',
                     'v': b'\v', 'a': b'\a', '\\': b'\\', '"': b'"'}
            data, index = bytearray(), 0
            while index < len(body):
                if body[index] == '\\':
                    octal = re.match(r'\\([0-7]{3})', body[index:])
                    if octal:
                        data.append(int(octal[1], 8)); index += 4; continue
                    index += 1
                    data.extend(table.get(body[index], body[index].encode('utf-8')))
                else:
                    data.extend(body[index].encode('utf-8'))
                index += 1
            value = data.decode('utf-8', errors='surrogateescape')
        return value[2:] if value.startswith(('a/', 'b/')) else value
    old_left = new_left = 0   # body lines still expected in the current hunk
    for line in raw.decode('utf-8', errors='replace').splitlines():
        if old_left > 0 or new_left > 0:
            # Hunk body: count lines so that content such as "--- x" is never read as a header.
            hunk = hunks[-1]
            tag, text = line[:1], line[1:]
            if tag == '\\':
                continue
            if tag in (' ', ''):
                old_line += 1; new_line += 1; old_left -= 1; new_left -= 1
                continue
            version, number = ('base', old_line) if tag == '-' else ('candidate', new_line)
            if tag == '-':
                old_line += 1; old_left -= 1
            else:
                new_line += 1; new_left -= 1
            stripped = text.strip()
            if not stripped or stripped.startswith(('//', '/*', '*')):
                continue   # blank and comment-only lines carry no behaviour
            hunk['removed' if tag == '-' else 'added'].append(number)
            define = re.match(r'\s*#\s*define\s+([A-Za-z_]\w*)', text)
            if define:
                hunk['define_lines'][version].append(number)
                if define[1] not in hunk['defines']:
                    hunk['defines'].append(define[1])
            continue
        if line.startswith('diff --git '):
            filename, old_filename = None, None
        if line.startswith('--- '):
            old_filename = parse_path(line[4:])
        if line.startswith('+++ '):
            filename = parse_path(line[4:]) or old_filename
        match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)', line)
        if match:
            before, before_count, after, after_count, context = match.groups()
            old_line, new_line = int(before), int(after)
            old_left, new_left = int(before_count or 1), int(after_count or 1)
            hunks.append({'id': f'h{len(hunks) + 1}', 'file': filename, 'old_file': old_filename,
                          'before': {'start': int(before), 'count': old_left},
                          'after': {'start': int(after), 'count': new_left}, 'context': context.strip(),
                          'removed': [], 'added': [], 'defines': [],
                          'define_lines': {'base': [], 'candidate': []}})
    return hunks


def version_record(dest, folder, out, version, commit, requested_ref, dirty):
    """Manifest, tar archive and provenance record for one materialized version tree."""
    manifest = tree_hashes(dest)
    manifest_path = folder / f'{version}.manifest.json'
    write_json(manifest_path, manifest)
    tar_path = folder / f'{version}.tar'
    with tarfile.open(tar_path, 'w') as tar:
        for item in sorted(dest.rglob('*')):
            tar.add(item, arcname=str(item.relative_to(dest)), recursive=False)
    return {'commit': commit, 'requested_ref': requested_ref, 'dirty': dirty,
            'path': str(dest.relative_to(out)), 'archive': str(tar_path.relative_to(out)),
            'archive_sha256': digest(tar_path), 'manifest': str(manifest_path.relative_to(out))}


def snapshot_versions(config, out, config_root):
    out, config_root = Path(out).resolve(), Path(config_root)
    folder = out / 'sources'
    folder.mkdir(parents=True, exist_ok=True)
    spec = config['source']
    repo = (config_root / spec['repo']).resolve()
    result = {}
    dirty_spec = spec.get('dirty')
    patch_spec = spec.get('patch')
    for version in ('base', 'candidate'):
        dest = folder / version
        if version == 'candidate' and patch_spec:
            # Candidate is base with an unseen diff applied (the --patch flow).
            dest.mkdir()
            apply_patch_tree(folder / 'base', patch_spec, dest)
            commit = result['base']['commit']
            (folder / 'candidate.applied.patch').write_bytes(Path(patch_spec).read_bytes())
            result[version] = version_record(dest, folder, out, version, commit,
                                             f'base+patch:{Path(patch_spec).name}', dirty=False)
            continue
        ref = spec[version]
        if ref.startswith('-'):
            raise ConfigError(f'unsafe Git ref: {ref}')
        try:
            commit = git(repo, 'rev-parse', '--verify', ref + '^{commit}').decode().strip()
        except ConfigError as exc:
            raise ConfigError(f'source.{version}: unknown Git ref {ref!r} in {repo} ({exc})') from exc
        dest.mkdir()
        export_tree(repo, commit, dest)
        dirty = bool(dirty_spec and dirty_spec['version'] == version)
        if dirty:
            dirty_repo = (config_root / dirty_spec['path']).resolve()
            if out.is_relative_to(dirty_repo):
                raise ConfigError('artifact output must be outside the dirty source repository')
            if git(dirty_repo, 'rev-parse', 'HEAD').decode().strip() != commit:
                raise ConfigError('dirty source HEAD must match the selected revision')
            shutil.rmtree(dest)
            copy_source(dirty_repo, dest)
            status = git(dirty_repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all')
            (folder / f'{version}.status.bin').write_bytes(status)
            (folder / f'{version}.dirty.patch').write_bytes(git(dirty_repo, 'diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD'))
        result[version] = version_record(dest, folder, out, version, commit, ref, dirty)
    with tempfile.TemporaryDirectory(prefix='patchcheck-diff-') as tmp:
        tmp = Path(tmp)
        git(tmp, 'init', '-q')
        git(tmp, 'config', 'user.name', 'Patchcheck snapshot')
        git(tmp, 'config', 'user.email', 'snapshot@example.invalid')
        for version in ('base', 'candidate'):
            for item in tmp.iterdir():
                if item.name != '.git':
                    shutil.rmtree(item) if item.is_dir() else item.unlink()
            copy_source(folder / version, tmp)
            # The synthetic source repository stores the bytes actually built.
            # Bypass ignore rules, attributes, clean filters and line conversion.
            git(tmp, 'read-tree', '--empty')
            entries = bytearray()
            for name, metadata in tree_hashes(tmp).items():
                oid = git(tmp, 'hash-object', '-w', '--no-filters', '--', name).strip()
                mode = b'100755' if metadata['executable'] else b'100644'
                entries.extend(mode + b' ' + oid + b'\t' + os.fsencode(name) + b'\0')
            git(tmp, 'update-index', '-z', '--index-info', input=bytes(entries))
            git(tmp, 'commit', '--allow-empty', '-qm', f'{version} exact snapshot')
            git(tmp, 'tag', version)
        raw = git(tmp, 'diff', '--no-ext-diff', '--no-textconv', '--binary', 'base', 'candidate')
        git(tmp, 'bundle', 'create', str(folder / 'snapshots.bundle'), '--all')
    diff_path = folder / 'versions.patch'
    diff_path.write_bytes(raw)
    if spec.get('diff'):
        supplied = (config_root / spec['diff']).read_bytes()
        with tempfile.TemporaryDirectory(prefix='patchcheck-verify-') as tmp:
            copy_source(folder / 'base', tmp)
            patch_path = folder / 'supplied.patch'
            patch_path.write_bytes(supplied)
            git(tmp, 'apply', '--check', str(patch_path))
            git(tmp, 'apply', str(patch_path))
            if tree_hashes(tmp) != tree_hashes(folder / 'candidate'):
                raise ConfigError('supplied diff does not produce the exact candidate source')
    hunks = parse_hunks(raw)
    result['diff'] = {'path': str(diff_path.relative_to(out)), 'sha256': digest(diff_path),
                      'hunks': hunks, 'source_map': annotate(hunks, folder / 'base', folder / 'candidate'),
                      'snapshot_bundle': 'sources/snapshots.bundle',
                      'tool_version': git(repo, '--version').decode().strip(),
                      'files': sorted(set(tree_hashes(folder / 'base')) | set(tree_hashes(folder / 'candidate')))}
    write_json(folder / 'versions.json', result)
    return result
