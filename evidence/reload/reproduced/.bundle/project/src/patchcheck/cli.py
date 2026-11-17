"""Public CLI. Infrastructure failures always return 30 with a clear message."""
import argparse
import sys
from pathlib import Path

from .contracts import ConfigError, load_config
from .pipeline import compare_report, run_pipeline
from .report import load_report, write_report


def main(argv=None):
    parser = argparse.ArgumentParser(prog='patchcheck', description='Automated security-patch validation and regression testing')
    sub = parser.add_subparsers(dest='operation', required=True)
    validate = sub.add_parser('validate-config')
    validate.add_argument('config')
    for name in ('build', 'run'):
        command = sub.add_parser(name)
        command.add_argument('config')
        command.add_argument('--out', required=True)
        command.add_argument('--base', help='Git ref overriding source.base in the config')
        command.add_argument('--candidate', help='Git ref overriding source.candidate (e.g. a patch to evaluate)')
        command.add_argument('--patch', help='Unified diff file applied to base as the candidate '
                                             '(for unseen patches; cannot combine with --candidate)')
    for name in ('compare', 'report'):
        command = sub.add_parser(name)
        command.add_argument('report')
    replay = sub.add_parser('replay')
    replay.add_argument('report')
    replay.add_argument('--test', required=True)
    replay.add_argument('--count', type=int, default=3)
    minimize = sub.add_parser('minimize')
    minimize.add_argument('report')
    minimize.add_argument('--test', required=True)
    bundle = sub.add_parser('bundle')
    bundle.add_argument('report')
    bundle.add_argument('--out', required=True)
    reproduce = sub.add_parser('reproduce')
    reproduce.add_argument('bundle')
    reproduce.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'validate-config':
            config = load_config(args.config)
            print(f'Configuration valid: {config["target"]}; build/environment validation occurs during build/run.')
            return 0
        if args.operation in ('run', 'build'):
            patch = str(Path(args.patch).resolve()) if args.patch else None
            report = run_pipeline(args.config, args.out, build_only=args.operation == 'build',
                                  base=args.base, candidate=args.candidate, patch=patch)
            print(f'{report["target"]}: exit {report["exit_code"]}; {Path(args.out).resolve() / "report.json"}')
            return (30 if report['technical_errors'] else 0) if args.operation == 'build' else report['exit_code']
        if args.operation in ('compare', 'report'):
            report = load_report(args.report)
            if args.operation == 'compare':
                compare_report(report)
                write_report(report, Path(args.report).resolve().parent)
            print((Path(args.report).resolve().parent / 'summary.md').read_text())
            return report['exit_code']
        if args.operation == 'replay':
            from .replay import replay_case
            result = replay_case(args.report, args.test, args.count)
            print(f'Replay: {result["status"]}; {len(result["run_ids"])} executions')
            return load_report(args.report)['exit_code']
        if args.operation == 'minimize':
            from .minimize import minimize_case
            result = minimize_case(args.report, args.test)
            print(f'Minimization: {result["status"]}; {result["original_size"]} -> {result["minimized_size"]} bytes')
            return load_report(args.report)['exit_code']
        if args.operation == 'bundle':
            from .bundle import make_bundle
            print(make_bundle(args.report, args.out))
            return 0
        if args.operation == 'reproduce':
            from .bundle import reproduce
            result = reproduce(args.bundle, args.out)
            print(f'Reproduced: exit {result["exit_code"]}; {args.out}')
            return result['exit_code']
    except (ConfigError, OSError, ValueError) as exc:
        print(f'BUILD_OR_CONFIG_ERROR: {exc}', file=sys.stderr)
        return 30


if __name__ == '__main__':
    raise SystemExit(main())
