"""Bounded delta debugging; only definite identical-signature matches survive."""
import math
import time
import uuid
from pathlib import Path

from .analysis import match_failure, reproduces, security_observation, uncertain_observation
from .contracts import ConfigError
from .pipeline import compare_report, execute_test
from .replay import replay_case
from .report import load_report, write_report
from .store import bytes_digest, checked_path, digest, read_json, write_json


def ddmin(data, predicate, *, max_attempts, wall_seconds):
    started, history = time.monotonic(), []
    original, current, granularity = data, data, 2

    def attempt(candidate):
        if len(history) >= max_attempts or time.monotonic() - started >= wall_seconds:
            return None
        result = predicate(candidate)
        if result not in ('match', 'mismatch', 'unknown'):
            raise ConfigError('match_failure predicate must return match, mismatch or unknown')
        history.append({'attempt': len(history) + 1, 'size': len(candidate), 'sha256': bytes_digest(candidate),
                        'result': result, 'elapsed_seconds': time.monotonic() - started})
        if history[-1]['elapsed_seconds'] >= wall_seconds:
            return None
        return result

    initial = attempt(current)
    if initial is None:
        return {'data': current, 'status': 'budget_exhausted', 'validated': False, 'history': history}
    if initial != 'match':
        return {'data': current, 'status': 'initial_not_matched', 'validated': False, 'history': history}
    exhausted = False
    while current:
        chunk = max(1, math.ceil(len(current) / granularity))
        reduced = False
        for start in range(0, len(current), chunk):
            candidate = current[:start] + current[start + chunk:]
            result = attempt(candidate)
            if result is None:
                exhausted = True
                break
            if result == 'match':
                current, granularity, reduced = candidate, max(2, granularity - 1), True
                break
        if exhausted:
            break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    exhausted = exhausted or time.monotonic() - started >= wall_seconds
    status = 'budget_exhausted' if exhausted else 'reduced' if len(current) < len(original) else 'no_reduction'
    return {'data': current, 'status': status, 'validated': not exhausted, 'history': history}


def minimize_case(report_path, test_id):
    """Minimize one test's crash input with bounded ddmin.

    Scope (see report['minimization_scope'] for per-finding coverage): this path
    only minimizes a security test (category original/minimized) that carries an
    explicit expected signature and reproduces that signature on the base/sanitized
    build. Candidate-only findings, functional regressions, release-only findings
    and findings without a matchable signature are out of scope and recorded with a
    reason in the report instead of being silently skipped.
    """
    report_path = Path(report_path).resolve()
    root = report_path.parent
    report = load_report(report_path)
    config = read_json(root / report['config'])
    original_test = next((t for t in report['tests'] if t['id'] == test_id), None)
    if original_test is None or not original_test['signature']:
        raise ConfigError('minimization requires a test with an explicit expected signature')
    if any(build['result'] != 'success' for build in report['builds']):
        raise ConfigError('minimization requires all four successful builds')
    token = uuid.uuid4().hex[:12]
    folder = root / 'minimization' / token
    folder.mkdir(parents=True)
    original = checked_path(root, original_test['input']).read_bytes()
    (folder / 'original.bin').write_bytes(original)
    baseline = next(b for b in report['builds'] if b['version'] == 'base' and b['build_type'] == 'sanitized')
    attempts = []

    def predicate(data):
        number = len(attempts) + 1
        path = folder / 'attempts' / f'{number:04d}.bin'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        case = {**original_test, 'input': str(path.relative_to(root)), 'sha256': digest(path), 'size': len(data)}
        run = execute_test(config, root, baseline, case, replay_of='minimization:' + test_id)
        report['runs'].append(run)
        result = match_failure(original_test['signature'], security_observation(run))
        attempts.append({'input': case['input'], 'run_id': run['id'], 'match_failure': result})
        if run['runner_error']:
            report['technical_errors'].append(run['id'] + ': ' + run['runner_error'])
        return result

    minimized = ddmin(original, predicate, **config['minimization'])
    data = minimized.pop('data')
    path = folder / 'minimized.bin'
    path.write_bytes(data)
    test = {**original_test, 'id': 'min-' + token, 'category': 'minimized',
            'input': str(path.relative_to(root)), 'sha256': digest(path), 'size': len(data),
            'origin': 'automatic-minimization', 'regression': {'signature': original_test['signature'],
                       'base_match_required': True, 'candidate_absence_and_oracle_required': True}}
    final_runs = []
    if minimized['validated']:
        report['tests'].append(test)
        for build in report['builds']:
            run = execute_test(config, root, build, test)
            report['runs'].append(run)
            final_runs.append(run)
        # The signature comes from the sanitized build; require reproduction there.
        # A release build may not surface the bug (e.g. an ASan-only out-of-bounds read).
        base_ok = all(reproduces(test['signature'], run) == 'match'
                      for run in final_runs if run['version'] == 'base' and run['build_type'] == 'sanitized')
        candidate_ok = all(run['oracle']['status'] == 'pass' and not security_observation(run)
                           and not uncertain_observation(run)
                           and not run['signal'] and run['resource_status'] == 'ok'
                           for run in final_runs if run['version'] == 'candidate')
        if not (base_ok and candidate_ok):
            minimized.update(validated=False, status='paired_validation_failed')
    result = {**minimized, 'id': token, 'test_id': test_id, 'minimized_test_id': test['id'] if final_runs else None,
              'original': str((folder / 'original.bin').relative_to(root)),
              'minimized': str(path.relative_to(root)), 'original_sha256': bytes_digest(original),
              'minimized_sha256': digest(path), 'original_size': len(original), 'minimized_size': len(data),
              'attempt_evidence': attempts, 'settings': config['minimization'], 'registered': False,
              'paired_run_ids': [run['id'] for run in final_runs]}
    report['minimized'].append(result)
    write_json(folder / 'minimization.json', result)
    compare_report(report)
    write_report(report, root)
    if result['validated']:
        replay = replay_case(report_path, test['id'], 3)
        report = load_report(report_path)
        result = report['minimized'][-1]
        if replay['status'] != 'stable':
            result.update(validated=False, status='unstable')
        else:
            corpus = Path(config['corpus_dir']).resolve()
            corpus.mkdir(parents=True, exist_ok=True)
            name = 'generated-' + result['minimized_sha256'][:16]
            (corpus / (name + '.bin')).write_bytes(data)
            write_json(corpus / (name + '.oracle.json'), test['oracle'])
            manifest = {'id': name, 'category': 'minimized', 'input': name + '.bin',
                        'sha256': test['sha256'], 'oracle': name + '.oracle.json', 'signature': test['signature'],
                        'input_mode': test.get('input_mode'), 'origin': 'automatic-minimization',
                        'regression': test['regression']}
            # Manifests use a distinct extension, so oracle files are never
            # mistaken for tests when loading the corpus.
            write_json(corpus / (name + '.test.json'), manifest)
            result.update(registered=True, corpus_manifest=str(corpus / (name + '.test.json')))
        write_json(folder / 'minimization.json', result)
        write_report(report, root)
    return result
