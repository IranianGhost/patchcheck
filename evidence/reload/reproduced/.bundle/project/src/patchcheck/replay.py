"""At least three additional paired executions with explicit stability evidence."""
from pathlib import Path

from .analysis import security_observation
from .contracts import ConfigError
from .pipeline import compare_report, execute_test
from .report import load_report, write_report
from .store import read_json, write_json


def validate_count(count):
    if isinstance(count, bool) or not isinstance(count, int) or count < 3:
        raise ConfigError('replay count must be at least 3 additional executions')


def comparable(run):
    """What must be identical across replays of one cell.

    A classified crash is compared by what failed and where (error type,
    detector, access kind, signature) instead of raw stderr bytes, because
    sanitizer reports contain memory addresses that change with ASLR.
    """
    keys = ('exit_code', 'signal', 'timeout', 'resource_status', 'output_truncated',
            'runner_error', 'stdout_sha256')
    analysis = run.get('analysis', {})
    crashes = [{'error_type': o['error_type'], 'detection_method': o['detection_method'],
                'access': (o.get('access') or {}).get('kind'), 'signature': o.get('signature')}
               for o in analysis.get('observations', []) if o.get('confirmation') == 'confirmed']
    value = {**{key: run.get(key) for key in keys},
             'signature': analysis.get('fixture_observation', {}).get('signature')
                          if analysis.get('fixture_observation') else None}
    if crashes:
        value['crashes'] = crashes
    else:
        value['stderr_sha256'] = run.get('stderr_sha256')
    return value


def stability(records):
    if len(records) < 3:
        return {'status': 'unknown', 'complete': False, 'reason': 'fewer than three records'}
    values = [comparable(run) for run in records]
    same = all(value == values[0] for value in values)
    complete = all(not run.get('runner_error') and not run.get('timeout') and
                   not run.get('output_truncated') and run.get('resource_status') == 'ok' for run in records)
    return {'status': 'stable' if same else 'unstable', 'complete': complete,
            'compared': values, 'ignored_fields': ['duration_seconds', 'rusage', 'sandbox.name']}


def stability_required(test, build, records):
    """A base build of a security test that never shows a confirmed crash carries
    no crash evidence for the finding; an out-of-bounds read there does not crash
    but prints the bytes it read, so its output is nondeterministic and its
    instability must not be held against the finding (e.g. giflib release)."""
    return not (test['category'] in ('original', 'minimized') and build['version'] == 'base'
                and not any(security_observation(run) for run in records))


def replay_case(report_path, test_id, count=3):
    validate_count(count)
    report_path = Path(report_path).resolve()
    root = report_path.parent
    report = load_report(report_path)
    config = read_json(root / report['config'])
    test = next((test for test in report['tests'] if test['id'] == test_id), None)
    if test is None:
        raise ConfigError(f'unknown replay test: {test_id}')
    groups, run_ids = [], []
    for build in report['builds']:
        if build['result'] != 'success':
            raise ConfigError('replay requires all four successful builds')
        original = next((run for run in report['runs'] if run['test_id'] == test_id and run['build_id'] == build['id']
                         and run['replay_of'] is None), None)
        if original is None:
            raise ConfigError('replay requires the original execution matrix')
        records = [original]
        for _ in range(count):
            run = execute_test(config, root, build, test, replay_of=original['id'])
            report['runs'].append(run)
            records.append(run)
            run_ids.append(run['id'])
            if run['runner_error']:
                report['technical_errors'].append(run['id'] + ': ' + run['runner_error'])
        groups.append({'build_id': build['id'], 'original_run_id': original['id'],
                       'run_ids': [run['id'] for run in records[1:]], **stability(records),
                       'stability_required': stability_required(test, build, records)})
    required = [group for group in groups if group['stability_required']]
    status = 'unstable' if any(group['status'] == 'unstable' for group in required) else 'stable'
    if status == 'stable' and not all(group['complete'] for group in required):
        status = 'unknown'
    result = {'test_id': test_id, 'input_sha256': test['sha256'], 'additional_count_per_cell': count,
              'status': status, 'groups': groups, 'run_ids': run_ids,
              'finding_ids': [f['id'] for f in report['findings'] if any(test_id == r['test_id'] and r['id'] in f['base_run_ids'] for r in report['runs'])]}
    report['replays'].append(result)
    if status == 'unstable' and test_id not in report['unstable']:
        report['unstable'].append(test_id)
    for finding in report['findings']:
        if finding['id'] in result['finding_ids']:
            finding['replay_stability'] = status
            if status != 'stable':
                finding['status'] = 'Inconclusive'
                finding['complete_evidence'] = False
    compare_report(report)
    folder = root / 'replays'
    write_json(folder / f'{test_id}-{len(report["replays"])}.json', result)
    write_report(report, root)
    return result
