"""Measure unit-test coverage with the optional `coverage` tool.

Install (once, opt-in):
    .venv/bin/pip install 'coverage[toml]'

Usage:
    .venv/bin/python ci/measure_coverage.py               # report to stdout
    .venv/bin/python ci/measure_coverage.py --html        # also write htmlcov/
    .venv/bin/python ci/measure_coverage.py --fail-under 80

The threshold is opt-in (default 0 = report only) so CI is never broken by a
coverage number; configuration lives in pyproject.toml under [tool.coverage.*].

This file is deliberately NOT named `coverage.py`: doing so would shadow the
`coverage` package on sys.path and defeat the availability check below.
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
    parser.add_argument('--fail-under', type=int, default=0,
                        help='exit non-zero when the reported percentage is below N (default: report only)')
    parser.add_argument('--html', action='store_true', help='also generate htmlcov/')
    args = parser.parse_args()

    if importlib.util.find_spec('coverage') is None:
        print("'coverage' is not installed. Install it once with:  .venv/bin/pip install 'coverage[toml]'",
              file=sys.stderr)
        return 2

    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    run = [sys.executable, '-m', 'coverage', 'run', '--branch',
           '-m', 'unittest', 'discover', '-s', 'tests/unit']
    subprocess.run(run, cwd=ROOT, env=env, check=True)

    report = [sys.executable, '-m', 'coverage', 'report', '--show-missing']
    if args.fail_under:
        report += ['--fail-under', str(args.fail_under)]
    code = subprocess.run(report, cwd=ROOT, env=env).returncode

    if args.html:
        subprocess.run([sys.executable, '-m', 'coverage', 'html'], cwd=ROOT, env=env, check=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
