"""Atomic structured records and confined, immutable evidence references."""
import hashlib
import json
import os
import tempfile
from pathlib import Path

from .contracts import ConfigError


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def bytes_digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_path(root, reference):
    root = Path(root).resolve()
    if Path(reference).is_absolute():
        raise ConfigError(f'artifact reference must be relative: {reference}')
    path = (root / reference).resolve()
    if not path.is_relative_to(root):
        raise ConfigError(f'artifact path escapes its root: {reference}')
    return path


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ConfigError(f'Cannot read JSON {path}: {exc}') from exc


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n'
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as stream:
            temporary = stream.name
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except (OSError, TypeError, ValueError) as exc:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
        raise ConfigError(f'Cannot serialize {path}: {exc}') from exc


def evidence_index(root):
    root = Path(root)
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*'))
            if p.is_file() and not p.is_symlink() and p.name not in ('report.json', 'summary.md')
            and 'bundles' not in p.relative_to(root).parts}


def verify_evidence(root, index):
    for reference, expected in index.items():
        path = checked_path(root, reference)
        if not path.is_file() or digest(path) != expected:
            raise ConfigError(f'missing or changed evidence: {reference}')
