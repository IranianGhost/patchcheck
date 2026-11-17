"""Run mutation testing with the optional `mutmut` tool.

Mutation testing makes small changes to the source and checks that at least one
test fails for each mutant; a mutant that no test catches is a coverage gap.

Install (once, opt-in):
    .venv/bin/pip install mutmut

Usage:
    .venv/bin/python ci/mutate.py                        # mutate src/patchcheck
    .venv/bin/python ci/mutate.py --paths-to-mutate src/patchcheck/decision.py

The unit tests are the mutation test suite; PYTHONPATH is set so `patchcheck`
resolves from src/. This is a developer tool and is intentionally not part of
the default CI pipeline.
"""
import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--paths-to-mutate', default='src/patchcheck',
                        help='comma-separated paths to mutate (default: src/patchcheck)')
    args = parser.parse_args()

    if importlib.util.find_spec('mutmut') is None:
        print("'mutmut' is not installed. Install it once with:  .venv/bin/pip install mutmut",
              file=sys.stderr)
        return 2

    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    runner = f'{sys.executable} -m unittest discover -s tests/unit'
    run = [sys.executable, '-m', 'mutmut', 'run',
           '--paths-to-mutate', args.paths_to_mutate,
           '--runner', runner]
    subprocess.run(run, cwd=ROOT, env=env, check=True)
    return subprocess.run([sys.executable, '-m', 'mutmut', 'results'], cwd=ROOT, env=env).returncode


if __name__ == '__main__':
    raise SystemExit(main())
