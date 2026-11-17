"""Offline, checksum-verified installation into the caller's virtualenv."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def bootstrap():
    if sys.version_info < (3, 11):
        raise SystemExit('Python >=3.11 is required; no host Python packages are modified.')
    wheels = ROOT / 'vendor/wheels'
    hashes = json.loads((wheels / 'SHA256SUMS.json').read_text())
    for name, expected in hashes.items():
        path = wheels / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit('wheel checksum mismatch: ' + name)
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--find-links', str(wheels),
                    '-r', str(ROOT / 'requirements.lock'), 'setuptools==75.8.0', 'wheel==0.45.1'], check=True)
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-build-isolation', '-e', str(ROOT)], check=True)


if __name__ == '__main__':
    bootstrap()
