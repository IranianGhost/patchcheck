"""Configuration-only target onboarding and evidence-preserving execution matrix."""
import shutil
import uuid
from pathlib import Path

from .analysis import (analyze, correlate, fixture_observation, match_failure, reproduces, same_failure,
                       security_observation, uncertain_observation)
from .build import build_all
from .contracts import ConfigError, load_config, validate, validate_id
from .coverage import parse_gcov
from .elf import compare_hardening
from .decision import decide, functional_pair
from .oracle import evaluate_oracle
from .report import load_report, write_report
from .sandbox import Sandbox
from .source import copy_source
from .store import bytes_digest, checked_path, digest, read_json, write_json


def prepare_tests(config, config_root, root):
    specs = [(test, config_root, 'configured') for test in config['tests']]
    corpus = (config_root / config['corpus_dir']).resolve()
    if corpus.exists():
        for manifest in sorted(corpus.glob('*.test.json')):
            value = read_json(manifest)
            validate('TargetConfig', {**config, 'tests': [value]})
            specs.append((value, manifest.parent, 'generated-regression'))
    tests, ids = [], set()
    for spec, base, origin in specs:
        if spec['id'] in ids:
            raise ConfigError(f'duplicate configured/corpus test id: {spec["id"]}')
        ids.add(spec['id'])
        folder = root / 'inputs' / spec['id']
        folder.mkdir(parents=True)
        source = (base / spec['input']).resolve()
        if origin == 'generated-regression' and not source.is_relative_to(base.resolve()):
            raise ConfigError('generated corpus input escapes corpus directory')
        dest = folder / 'original.bin'
        shutil.copyfile(source, dest)
        if spec.get('sha256') and digest(dest) != spec['sha256']:
            raise ConfigError(f'input hash mismatch: {spec["id"]}')
        oracle = read_json(base / spec['oracle']) if spec['oracle'] is not None else None
        if oracle:
            write_json(folder / 'oracle.json', oracle)
        test = {'schema_version': '1.0', 'id': spec['id'], 'target': config['target'],
                'category': spec['category'], 'input': str(dest.relative_to(root)),
                'sha256': digest(dest), 'size': dest.stat().st_size,
                'input_mode': spec.get('input_mode', config['input']['mode']), 'oracle': oracle,
                'signature': spec['signature'], 'origin': origin, 'regression': spec.get('regression')}
        validate('TestCase', test)
        write_json(folder / 'test.json', test)
        tests.append(test)
    return tests


def execute_test(config, root, build, test, *, replay_of=None, run_id=None):
    root = Path(root)
    binary = checked_path(root, build['binary'])
    input_path = checked_path(root, test['input'])
    if digest(binary) != build['binary_sha256'] or digest(input_path) != test['sha256']:
        raise ConfigError('binary or test input changed since recording')
    mode = test['input_mode']
    input_value = '/case-input'
    if mode == 'argv':
        data = input_path.read_bytes()
        try:
            input_value = data.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ConfigError('argv input must be UTF-8') from exc
        if '\0' in input_value or len(data) > 32768:
            raise ConfigError('argv input contains NUL or exceeds 32768 bytes')
    # Replacing placeholders in list elements never invokes a shell. Payloads
    # containing quotes, $, spaces or newlines remain one argument.
    command = [argument.replace('{binary}', '/binary').replace('{input}', input_value)
               for argument in config['input']['argv']]
    source_dir = checked_path(root, build['source']['path'])
    cwd = (source_dir / config['input']['cwd']).resolve()
    if not cwd.is_relative_to(source_dir.resolve()) or not cwd.is_dir():
        raise ConfigError('runtime cwd escapes or does not exist in source snapshot')
    box = Sandbox(config['environment']['image'], config['limits'], image_info=build['environment']['image'])
    result = box.execute(command, cwd, env=config['environment']['variables'],
                         stdin=input_path if mode == 'stdin' else None,
                         mounts=[(binary, '/binary'), (input_path, '/case-input')])
    run_id = run_id or f'{test["id"]}-{build["id"]}-{uuid.uuid4().hex[:12]}'
    validate_id(run_id)
    folder = root / 'runs' / run_id
    folder.mkdir(parents=True)
    stdout, stderr = result.pop('stdout_bytes'), result.pop('stderr_bytes')
    (folder / 'stdout.bin').write_bytes(stdout)
    (folder / 'stderr.bin').write_bytes(stderr)
    write_json(folder / 'measurement.json', result)
    record = {'schema_version': '1.0', 'id': run_id, 'version': build['version'],
              'build_type': build['build_type'], 'build_id': build['id'], 'test_id': test['id'],
              'input': test['input'], 'input_sha256': test['sha256'], 'command': command,
              'cwd': '/work', 'environment': result['effective_env'], 'limits': config['limits'],
              **{key: result[key] for key in ('duration_seconds', 'exit_code', 'signal', 'timeout',
                                             'resource_status', 'output_truncated', 'runner_error', 'rusage', 'sandbox')},
              'stdout': str((folder / 'stdout.bin').relative_to(root)),
              'stderr': str((folder / 'stderr.bin').relative_to(root)),
              'stdout_sha256': digest(folder / 'stdout.bin'), 'stderr_sha256': digest(folder / 'stderr.bin'),
              'diagnostics': [], 'trace': [], 'oracle': {}, 'analysis': {}, 'replay_of': replay_of}
    if any(marker in stderr for marker in (b'AddressSanitizer', b'UndefinedBehaviorSanitizer', b'runtime error:')):
        record['diagnostics'].append(record['stderr'])
    record['oracle'] = evaluate_oracle(record, test['oracle'], root)
    record['analysis'] = analyze(record, stderr)
    if config['fixture'] and 'fixture-marker' in config['analyzers']:
        record['analysis']['fixture_observation'] = fixture_observation(record, stderr)
    validate('RunRecord', record)
    write_json(folder / 'run.json', record)
    return record


SECURITY_CATEGORIES = ('original', 'minimized')   # inputs that target the vulnerability
# A changed answer on an invalid input is not a code-20 regression (that needs a
# valid/boundary test), but it blocks a definite verdict.
FUNCTIONAL_UNKNOWN = ('unknown', 'both_fail', 'baseline_fail', 'invalid_behavior_changed')
ISSUE_STATUSES = ('Incomplete Fix', 'New Issue')


def describe_location(obs):
    loc = obs.get('location')
    if isinstance(loc, dict) and loc.get('function'):
        return f'{loc["file"]}:{loc["line"]} in {loc["function"]}'
    if isinstance(loc, dict):
        return f'{loc["file"]}:{loc["line"]}'
    return loc or (obs.get('signature') or {}).get('location')


def security_finding(test, kind, base, candidate, replay_status):
    """Compare the failures of one base/candidate pair; None if neither failed abnormally."""
    b, c = security_observation(base), security_observation(candidate)
    if b and not c:
        status, obs = ('Inconclusive' if uncertain_observation(candidate) else 'Fixed'), b
    elif b and c:
        relation = same_failure(b, c)
        status = {'match': 'Incomplete Fix', 'mismatch': 'New Issue'}.get(relation, 'Inconclusive')
        obs = c
    elif c:
        status, obs = 'New Issue', c
    else:
        obs = uncertain_observation(candidate)
        if obs is None:
            return None
        status = 'Inconclusive'  # a crash without detector evidence is not a confirmed vulnerability
    unstable = replay_status in ('unstable', 'unknown')
    fixture = obs.get('confirmation') == 'fixture'
    if fixture or unstable:
        status = 'Inconclusive'
    confirmation = 'fixture' if fixture else 'unknown' if unstable or obs.get('confirmation') != 'confirmed' else 'confirmed'
    signature = obs.get('signature')
    sufficiency = 'fixture_only' if fixture else 'sufficient' if signature and not unstable else 'insufficient'
    finding = {'schema_version': '1.0', 'id': f'finding-security-{test["id"]}-{kind}',
               'error_type': obs['error_type'] if 'error_type' in obs else signature['error_type'],
               'detection_method': obs.get('detection_method', 'explicit-fixture-protocol'),
               'confirmation': confirmation, 'signature': signature, 'location': describe_location(obs),
               'base_run_ids': [base['id']], 'candidate_run_ids': [candidate['id']],
               'replay_stability': replay_status, 'status': status, 'root_cause': None,
               'evidence_sufficiency': sufficiency,
               'evidence': [base['stderr'], candidate['stderr'], base['stdout'], candidate['stdout']],
               'complete_evidence': bool(signature) and not unstable and not fixture}
    validate('Finding', finding)
    return finding


def functional_finding(test, kind, base, candidate, replay_status):
    stable = replay_status not in ('unstable', 'unknown')
    finding = {'schema_version': '1.0', 'id': f'finding-functional-{test["id"]}-{kind}',
               'error_type': 'functional-regression', 'detection_method': 'independent-oracle',
               'confirmation': 'confirmed' if stable else 'unknown', 'signature': None, 'location': None,
               'base_run_ids': [base['id']], 'candidate_run_ids': [candidate['id']],
               'replay_stability': replay_status,
               'status': 'Functional Regression' if stable else 'Inconclusive', 'root_cause': None,
               'evidence_sufficiency': 'sufficient' if stable else 'insufficient',
               'evidence': [base['stderr'], candidate['stderr'], base['stdout'], candidate['stdout']],
               'complete_evidence': stable}
    validate('Finding', finding)
    return finding


def target_reproduced(test, run):
    """Base run shows the declared target error (any confirmed crash if none is declared)."""
    obs = security_observation(run)
    if not obs or obs.get('confirmation') != 'confirmed':
        return False
    return match_failure(test['signature'], obs) == 'match' if test['signature'] else True


def compare_report(report):
    pairs, findings, reasons = [], [], []
    security_tests = [t for t in report['tests'] if t['category'] in SECURITY_CATEGORIES]
    for test in report['tests']:
        for kind in ('release', 'sanitized'):
            paired = [next((r for r in report['runs'] if r['test_id'] == test['id']
                            and r['version'] == version and r['build_type'] == kind and r['replay_of'] is None), None)
                      for version in ('base', 'candidate')]
            if any(run is None for run in paired):
                continue
            base, candidate = paired
            base_status, candidate_status = base['oracle']['status'], candidate['oracle']['status']
            observed_status = functional_pair(base_status, candidate_status, test['category'])
            relevant_replays = [r for r in report.get('replays', []) if r['test_id'] == test['id']]
            unstable = test['id'] in report.get('unstable', []) or any(r['status'] == 'unstable' for r in relevant_replays)
            replay_unknown = any(r['status'] == 'unknown' for r in relevant_replays)
            replay_status = 'unstable' if unstable else 'unknown' if replay_unknown else 'stable' if relevant_replays else 'not_run'
            status = 'unknown' if unstable or replay_unknown else observed_status
            pair = {'test_id': test['id'], 'build_type': kind, 'base': base_status,
                    'candidate': candidate_status, 'status': status, 'observed_status': observed_status,
                    'replay_stability': replay_status,
                    'base_run_id': base['id'], 'candidate_run_id': candidate['id']}
            if test['regression']:
                base_match = reproduces(test['signature'], base)
                # The signature is a sanitized-build crash. A release build has no
                # symbolized location, so it cannot confirm the *same* bug (its base
                # reproduction is `unknown` by construction). A release base is
                # accepted unless it ends with an unclassified termination (bare
                # signal/timeout/resource limit); the sanitized build remains the
                # authoritative reproduction check.
                base_ok = base_match == 'match' if kind == 'sanitized' else not uncertain_observation(base)
                clean_candidate = (candidate['oracle']['status'] == 'pass' and not security_observation(candidate)
                                   and not uncertain_observation(candidate)
                                   and candidate['resource_status'] == 'ok' and not candidate['signal'])
                pair['generated_regression'] = {'base_match': base_match,
                                                'candidate_absence_and_oracle': clean_candidate,
                                                'status': 'pass' if base_ok and clean_candidate
                                                          and not unstable and not replay_unknown else 'unknown'}
            pairs.append(pair)
            finding = security_finding(test, kind, base, candidate, replay_status)
            if finding:
                findings.append(finding)
            if test['category'] not in SECURITY_CATEGORIES and observed_status == 'regression':
                findings.append(functional_finding(test, kind, base, candidate, replay_status))

    security_ids = {test['id'] for test in security_tests}
    functional_pairs = [pair for pair in pairs if pair['test_id'] not in security_ids]
    security_oracle_failures = [pair for pair in pairs if pair['test_id'] in security_ids
                                and pair['candidate'] != 'pass']
    generated_failures = [pair for pair in pairs
                          if pair.get('generated_regression', {}).get('status', 'pass') != 'pass']
    regressions = [p for p in functional_pairs if p['status'] == 'regression']
    confirmed_issues = [f['id'] for f in findings if f['status'] in ISSUE_STATUSES and f['confirmation'] == 'confirmed']
    baseline_reproduced = any(target_reproduced(test, run) for test in security_tests for run in report['runs']
                              if run['test_id'] == test['id'] and run['version'] == 'base' and run['replay_of'] is None)

    # Everything that prevents a definite verdict, each with its cause.
    if len(pairs) != len(report['tests']) * 2:
        reasons.append('missing-executions: not every test ran on both versions in both builds')
    if not security_tests:
        reasons.append('no-security-tests: no original/minimized input targets the vulnerability')
    elif not baseline_reproduced:
        reasons.append('baseline-not-reproduced: the target error was not observed on the base version')
    # Required functional coverage (spec §3.2): valid, boundary and invalid inputs
    # must each be present; their independent oracle is enforced through the
    # functional-unknown reason when a pair is not adjudicable.
    present_categories = {test['category'] for test in report['tests']}
    for category in ('valid', 'boundary', 'invalid'):
        if category not in present_categories:
            reasons.append(f'missing-test-category: no {category} input is configured')
    # An unclassified termination (bare signal, timeout or resource limit) in any
    # executed cell is incomplete evidence and must block a definite verdict.
    for run in report['runs']:
        if run.get('replay_of') is not None:
            continue
        if uncertain_observation(run):
            reasons.append(f'unclassified-termination: {run["test_id"]} {run["version"]} {run["build_type"]}')
    reasons += [f'functional-unknown: {p["test_id"]} ({p["build_type"]}) base={p["base"]} candidate={p["candidate"]}'
                for p in functional_pairs if p['status'] in FUNCTIONAL_UNKNOWN]
    reasons += [f'security-input-oracle: {p["test_id"]} ({p["build_type"]}) candidate={p["candidate"]}'
                for p in security_oracle_failures]
    reasons += [f'generated-regression-incomplete: {p["test_id"]} ({p["build_type"]})'
                for p in generated_failures]
    reasons += [f'inconclusive-finding: {f["id"]}' for f in findings if f['status'] == 'Inconclusive']
    reasons += [f'unstable-replay: {test_id}' for test_id in report.get('unstable', [])]
    if report.get('fixture'):
        reasons.append('fixture-target: fixture evidence never validates a real patch')

    security_inconclusive = any(f['status'] == 'Inconclusive' and f['error_type'] != 'functional-regression'
                                for f in findings)
    security_status = 'issue' if confirmed_issues else \
        'fixed' if baseline_reproduced and not security_inconclusive else 'unknown'
    functional_status = 'regression' if regressions else \
        'unknown' if security_oracle_failures or generated_failures or \
        any(p['status'] in FUNCTIONAL_UNKNOWN for p in functional_pairs) or \
        len(pairs) != len(report['tests']) * 2 else 'preserved'
    # Release binaries of both versions: protection loss blocks PASS.
    builds = report.get('builds') or []
    release = {b['version']: b for b in builds if b['build_type'] == 'release' and b['result'] == 'success'}
    hardening = compare_hardening(release.get('base'), release.get('candidate')) if builds else \
        {**report.get('hardening', {}), 'interpretation': 'unknown'}
    reasons += [f'hardening-degraded: {d}' for d in hardening.get('degraded', [])]
    reasons += [f'hardening-unknown: {u}' for u in hardening.get('unknown', [])]
    report['hardening'] = hardening
    report['findings'] = findings
    report['patch_relations'] = correlate(report['diff'], findings, report['runs'])
    # Minimization coverage: which findings the automatic minimizer can target.
    # It accepts only a security test (original/minimized) with an explicit
    # signature whose sanitized base run reproduces that signature; everything
    # else is out of scope and recorded here with a reason and the finding id.
    runs_by_id = {run['id']: run for run in report['runs']}
    minimizable_tests = set()
    for test in security_tests:
        base_san = next((r for r in report['runs'] if r['test_id'] == test['id'] and r['version'] == 'base'
                         and r['build_type'] == 'sanitized' and r['replay_of'] is None), None)
        if test['signature'] and base_san and reproduces(test['signature'], base_san) == 'match':
            minimizable_tests.add(test['id'])
    report['minimization_scope'] = []
    for f in findings:
        test_id = None
        for run_id in f['base_run_ids'] + f['candidate_run_ids']:
            run = runs_by_id.get(run_id)
            if run:
                test_id = run['test_id']
                break
        if f['status'] == 'Functional Regression':
            covered, reason = False, 'functional regression has no crash signature to minimize'
        elif f['status'] == 'New Issue':
            covered, reason = False, 'documented out of scope: candidate-only finding has no base signature to reproduce'
        elif f['status'] == 'Inconclusive':
            covered, reason = False, 'insufficient evidence for minimization'
        elif f['id'].endswith('-release'):
            covered, reason = False, 'release finding has no symbolized location'
        elif test_id is not None and test_id in minimizable_tests:
            covered, reason = True, 'test has a matchable signature reproduced on the sanitized base'
        else:
            covered, reason = False, 'test has no matchable signature on the sanitized base'
        report['minimization_scope'].append({'finding_id': f['id'], 'covered': covered, 'reason': reason})
    report['axes'] = {'security': {'status': security_status, 'baseline_reproduced': baseline_reproduced,
                                  'confirmed_issues': confirmed_issues,
                                  'fixture_observations': sum(f['confirmation'] == 'fixture' for f in findings)},
                      'functional': {'status': functional_status, 'comparisons': pairs},
                      'completeness': {'complete': not reasons, 'reasons': reasons}}
    decision = decide({'technical_error': bool(report['technical_errors']),
                       'confirmed_security_issue': bool(confirmed_issues),
                       'functional_regression': bool(regressions),
                       'incomplete': bool(reasons), 'baseline_reproduced': baseline_reproduced,
                       'hardening_degraded': bool(hardening.get('degraded'))})
    report['axes']['functional']['decision_engine_code'] = decision
    report['exit_code'] = decision
    return report


def _normalize_coverage(covered, changed_files, all_sources=()):
    """Map gcov source paths onto git-diff paths by exact or unique-basename match.

    Returns ``(normalized, ambiguous)``. An explicit source path (with a directory
    component) is only kept when it exactly matches a changed file; it is never
    re-attributed to a same-named file. A bare basename is attributed only when it is
    unique across *all* sources of the build; otherwise it is recorded as ambiguous
    so the report can state the reason instead of guessing.
    """
    all_set = set(all_sources)
    by_basename = {}
    ambiguous_basenames = set()
    for f in all_set:
        base = Path(f).name
        if base in by_basename and by_basename[base] != f:
            ambiguous_basenames.add(base)
        else:
            by_basename[base] = f
    out = {}
    ambiguous = set()
    for raw, lines in covered.items():
        file = raw
        # Normalize a workdir/absolute prefix to the snapshot-relative path.
        if file.startswith('/work/'):
            file = file[len('/work/'):]
        elif file.startswith('/'):
            file = file.lstrip('/')
        file = file[2:] if file.startswith('./') else file
        if file in changed_files:
            out[file] = lines
            continue
        # Only a bare basename may fall back to a basename match; an explicit path
        # that is not changed must not be re-attributed to a same-named file.
        if '/' in file or '\\' in file:
            continue
        base = Path(file).name
        if base in ambiguous_basenames:
            ambiguous.add(base)
            continue
        if base not in by_basename:
            continue
        target = by_basename[base]
        if target in changed_files:
            out[target] = lines
    return out, sorted(ambiguous)


def collect_coverage(config, root, report):
    """Run each functional-regression input on a gcov-instrumented candidate.

    Returns a list of per-input coverage records so correlation attributes covered
    lines to the exact input that executed them. Each input gets a fresh workdir, so
    ``.gcda`` counters never leak between inputs. Empty list when the config declares
    no ``builds.coverage`` diagnostic build or there is no functional regression.
    """
    spec = (config.get('builds') or {}).get('coverage')
    if not spec:
        return []
    regressions = sorted({p['test_id'] for p in report['axes']['functional']['comparisons']
                          if p['status'] == 'regression'})
    if not regressions:
        return []
    root = Path(root)
    source_dir = checked_path(root, 'sources/candidate')
    tests = {t['id']: t for t in report['tests']}
    main_runs = {}
    for run in report['runs']:
        if run.get('replay_of') is None:
            main_runs[(run['test_id'], run['build_type'])] = run
    changed = sorted({h.get('file') or h.get('old_file') for h in report['diff'].get('hunks', [])
                      if h.get('file') or h.get('old_file')})
    box = Sandbox(config['environment']['image'], config['limits'])
    records = []

    for test_id in regressions:
        test = tests.get(test_id)
        if test is None:
            continue
        work = root / 'coverage' / test_id
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        copy_source(source_dir, work)
        command = []
        for argument in spec['command']:
            command.extend(spec['flags'] if argument == '{flags}' else
                           [spec['compiler'] if argument == '{compiler}' else argument])
        build_result = box.execute(command, work, env=config['environment']['variables'],
                                   writable=True, build=True)
        if build_result['exit_code'] != 0 or build_result['runner_error'] or build_result['timeout']                 or build_result['resource_status'] != 'ok':
            records.append({'test_id': test_id, 'input_sha256': test.get('sha256'), 'version': 'candidate',
                            'build_type': 'coverage', 'status': 'build-failed',
                            'reason': f'coverage build failed (exit {build_result.get("exit_code")})',
                            'coverage': {}})
            continue
        binary = work / spec['binary']
        input_path = checked_path(root, test['input'])
        input_value = '/case-input'
        if test['input_mode'] == 'argv':
            try:
                input_value = input_path.read_bytes().decode('utf-8')
            except UnicodeDecodeError:
                records.append({'test_id': test_id, 'input_sha256': test.get('sha256'), 'version': 'candidate',
                                'build_type': 'coverage', 'status': 'input-error',
                                'reason': 'argv input is not valid UTF-8', 'coverage': {}})
                continue
        run_command = [a.replace('{binary}', '/binary').replace('{input}', input_value)
                       for a in config['input']['argv']]
        # Match the main run's working directory; counters are moved back beside
        # the .gcno notes afterwards because the runtime cwd may differ from the
        # build cwd when input.cwd is not '.'.
        cwd = (work / config['input']['cwd']).resolve()
        if not cwd.is_relative_to(work.resolve()):
            records.append({'test_id': test_id, 'input_sha256': test.get('sha256'), 'version': 'candidate',
                            'build_type': 'coverage', 'status': 'input-error',
                            'reason': 'runtime cwd escapes the coverage workdir', 'coverage': {}})
            continue
        run_result = box.execute(run_command, cwd, env=config['environment']['variables'],
                                 stdin=input_path if test['input_mode'] == 'stdin' else None,
                                 mounts=[(binary, '/binary'), (input_path, '/case-input')], writable=True)
        for gcda in list(work.rglob('*.gcda')):
            if gcda.parent != work:
                shutil.move(str(gcda), str(work / gcda.name))
        # Evaluate the independent oracle on the diagnostic run so a confirmed
        # relation requires the same functional difference to be observable here.
        diag = work / 'diag'
        diag.mkdir(exist_ok=True)
        (diag / 'stdout.bin').write_bytes(run_result['stdout_bytes'])
        (diag / 'stderr.bin').write_bytes(run_result['stderr_bytes'])
        diag_run = {'exit_code': run_result.get('exit_code'), 'signal': run_result.get('signal'),
                    'timeout': run_result.get('timeout'), 'resource_status': run_result.get('resource_status'),
                    'output_truncated': run_result.get('output_truncated'),
                    'runner_error': run_result.get('runner_error'),
                    'stdout': 'diag/stdout.bin', 'stderr': 'diag/stderr.bin'}
        diagnostic_oracle = evaluate_oracle(diag_run, test.get('oracle'), work)['status']
        # gcov must be called with the translation-unit note file, not the source
        # path: a multi-file build with `-o` names its notes `<output>-<base>.gcno`.
        note_files = sorted(p.name for p in work.glob('*.gcno'))
        gcov = {'calls': [], 'note_files': note_files}

        def norm_source(pth):
            if pth.startswith('/work/'):
                pth = pth[len('/work/'):]
            elif pth.startswith('/'):
                pth = pth.lstrip('/')
            return pth[2:] if pth.startswith('./') else pth

        for note in note_files:
            before = set(p.name for p in work.rglob('*.gcov'))
            g = box.execute(['gcov', '-b', '-c', note], work, build=True, writable=True)
            after = set(p.name for p in work.rglob('*.gcov'))
            sources = []
            for name in after - before:
                try:
                    text = (work / name).read_text(errors='replace')
                    for line in text.splitlines():
                        idx = line.find('Source:')
                        if idx != -1:
                            sources.append(line[idx + len('Source:'):].strip())
                            break
                except OSError:
                    pass
            gcov['calls'].append({'note': note, 'exit_code': g['exit_code'],
                                  'stdout': g['stdout_bytes'].decode('utf-8', errors='replace'),
                                  'stderr': g['stderr_bytes'].decode('utf-8', errors='replace'),
                                  'sources': sorted(set(sources))})
        # A changed file whose gcov extraction failed must not confirm a relation.
        gcov_failed_files = []
        for call in gcov['calls']:
            if call['exit_code'] != 0:
                for src in call['sources']:
                    s = norm_source(src)
                    if s in changed:
                        gcov_failed_files.append(s)
        all_sources = sorted({str(p.relative_to(work)) for p in work.rglob('*')
                              if p.is_file() and p.suffix in ('.c', '.cpp', '.cc', '.h', '.hpp')})
        gcov_text = ''
        for gcov_file in sorted(work.rglob('*.gcov')):
            try:
                gcov_text += gcov_file.read_text(errors='replace') + '\n'
            except OSError:
                continue
        covered, ambiguous = _normalize_coverage(parse_gcov(gcov_text), changed, all_sources)
        evidence = [str(p.relative_to(root)) for p in sorted(work.rglob('*.gcov'))]
        if not covered:
            records.append({'test_id': test_id, 'input_sha256': test.get('sha256'), 'version': 'candidate',
                            'build_type': 'coverage', 'status': 'no-coverage',
                            'reason': 'gcov produced no coverage for a changed file', 'coverage': {},
                            'ambiguous': ambiguous, 'gcov': gcov, 'gcov_failed_files': gcov_failed_files,
                            'evidence': evidence})
            continue
        records.append({'test_id': test_id, 'input_sha256': test.get('sha256'), 'version': 'candidate',
                        'build_type': 'coverage', 'run_id': f'coverage-{test_id}-{uuid.uuid4().hex[:12]}',
                        'status': 'ok', 'diagnostic_exit_code': run_result.get('exit_code'),
                        'diagnostic_signal': run_result.get('signal'),
                        'diagnostic_oracle': diagnostic_oracle,
                        'coverage': {f: sorted(ls) for f, ls in covered.items()},
                        'ambiguous': ambiguous, 'gcov': gcov, 'gcov_failed_files': gcov_failed_files,
                        'evidence': evidence})
    return records


def run_pipeline(config_path, out, *, build_only=False, base=None, candidate=None, patch=None, followup=True):
    config_path = Path(config_path).resolve()
    root = Path(out).resolve()
    if root.exists() and any(root.iterdir()):
        raise ConfigError(f'output directory must be empty: {root}')
    root.mkdir(parents=True, exist_ok=True)
    # Build the report skeleton before loading the config so that a configuration,
    # build or environment error still produces a schema-valid report.json (exit
    # 30) whenever the output directory is writable.
    report = {'schema_version': '1.0', 'id': uuid.uuid4().hex, 'target': 'unknown', 'fixture': False,
              'config': 'config.json', 'versions': {}, 'environment': {}, 'builds': [], 'tests': [], 'runs': [],
              'axes': {}, 'findings': [], 'patch_relations': [], 'diff': {},
              'hardening': {'interpretation': 'unknown', 'comparison': 'not-run'},
              'replays': [], 'minimized': [], 'minimization_scope': [], 'bundles': [], 'unstable': [],
              'unknowns': ['Patch correlation uses static stacks and a lexical source map; code that returned '
                           'before a crash is not on its stack, and release builds have no stack.',
                           'Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof '
                           'that the protection is off.'],
              'technical_errors': [], 'evidence_index': {}, 'exit_code': 40, 'stage': 2}
    try:
        config = load_config(config_path)
        report['target'] = config['target']
        report['fixture'] = config['fixture']
        # Command-line refs replace the configured ones so one config can evaluate
        # any number of candidate patches; the effective refs are saved in config.json.
        for version, ref in (('base', base), ('candidate', candidate)):
            if ref is not None:
                if config['source'].get('diff') or config['source'].get('dirty'):
                    raise ConfigError(f'--{version} cannot be combined with source.diff or source.dirty')
                config['source'][version] = ref
        if patch is not None:
            # --patch evaluates an unseen diff applied to base; the candidate is base+patch.
            if candidate is not None or config['source'].get('diff') or config['source'].get('dirty'):
                raise ConfigError('--patch cannot be combined with --candidate or source.diff/source.dirty')
            config['source']['patch'] = patch
            config['source']['candidate'] = config['source']['base']
        resolved = {**config, 'source': dict(config['source'])}
        resolved['source']['repo'] = str((config_path.parent / config['source']['repo']).resolve())
        for key in ('diff', 'patch'):
            if resolved['source'].get(key):
                # A --patch path is already absolute (resolved by the CLI); a config diff is config-relative.
                resolved['source'][key] = str(Path(resolved['source'][key]) if Path(resolved['source'][key]).is_absolute()
                                              else (config_path.parent / resolved['source'][key]).resolve())
        if resolved['source'].get('dirty'):
            resolved['source']['dirty'] = {**resolved['source']['dirty'], 'path': str((config_path.parent / resolved['source']['dirty']['path']).resolve())}
        resolved['corpus_dir'] = str((config_path.parent / config['corpus_dir']).resolve())
        for test in resolved['tests']:
            test['input'] = str((config_path.parent / test['input']).resolve())
            if test['oracle']:
                test['oracle'] = str((config_path.parent / test['oracle']).resolve())
        write_json(root / 'config.json', resolved)
        # resolved paths remove any implicit dependence on the invoking cwd.
        builds, versions, environment = build_all(resolved, root, root)
        report.update(builds=builds, versions={v: versions[v] for v in ('base', 'candidate')},
                      diff=versions['diff'], environment=environment)
        for build in builds:
            if build['result'] != 'success':
                report['technical_errors'].append(build['id'] + ': ' + (build['error'] or 'build failed'))
        report['tests'] = prepare_tests(resolved, root, root)
        if not build_only:
            for test in report['tests']:
                for build in builds:
                    if build['result'] != 'success':
                        continue
                    run = execute_test(resolved, root, build, test)
                    report['runs'].append(run)
                    if run['runner_error']:
                        report['technical_errors'].append(run['id'] + ': ' + run['runner_error'])
    except (ConfigError, OSError) as exc:
        report['technical_errors'].append(str(exc))
        # Keep the report's config reference resolvable even when loading the
        # config itself failed before the resolved config could be written.
        if not (root / 'config.json').exists():
            write_json(root / 'config.json', {'error': str(exc), 'config_path': str(config_path)})
    compare_report(report)
    if not build_only and not report['technical_errors']:
        # Functional-regression correlation: add gcov execution-path evidence when a
        # coverage diagnostic build is configured, then re-decide with that evidence.
        try:
            coverage_runs = collect_coverage(resolved, root, report)
            if coverage_runs:
                report['diff'] = {**report.get('diff', {}),
                                  'coverage': {'build_type': 'coverage', 'runs': coverage_runs}}
                compare_report(report)
        except (ConfigError, OSError) as exc:
            report['technical_errors'].append(f'coverage collection failed: {exc}')
            compare_report(report)
    write_report(report, root)
    if followup and not build_only and not report['technical_errors']:
        try:
            report = replay_and_bundle(root / 'report.json')
        except (ConfigError, OSError) as exc:
            # Keep report.json consistent with the exit code: a failed follow-up is a tool error (30).
            report = load_report(root / 'report.json')
            report['technical_errors'].append(f'replay/bundle follow-up failed: {exc}')
            compare_report(report)
            write_report(report, root)
    return report

def confirmed_finding_tests(report):
    """Test ids of every test that produced a confirmed finding (security or functional regression)."""
    runs = {run['id']: run for run in report['runs']}
    tests = set()
    for finding in report['findings']:
        if finding['confirmation'] == 'confirmed':
            for run_id in finding['base_run_ids'] + finding['candidate_run_ids']:
                run = runs.get(run_id)
                if run:
                    tests.add(run['test_id'])
    return sorted(tests)


def replay_and_bundle(report_path):
    """Automatic §3.3 follow-up: replay every confirmed finding three extra times
    (re-deciding the verdict with replay stability), then produce one
    reproduction bundle that reproduces every confirmed error of this evaluation."""
    from .replay import replay_case          # local imports: replay/bundle import pipeline
    from .bundle import make_bundle
    report = load_report(report_path)
    root = Path(report_path).parent
    for test_id in confirmed_finding_tests(report):
        if not any(r['test_id'] == test_id and r['additional_count_per_cell'] >= 3 for r in report['replays']):
            replay_case(report_path, test_id, 3)
    report = load_report(report_path)
    if confirmed_finding_tests(report) and not report['bundles'] and not report['technical_errors']:
        make_bundle(report_path, root / 'reproduction.tar.gz',
                    include_image=all(f['error_type'] == 'functional-regression'
                                      for f in report['findings'] if f['confirmation'] == 'confirmed'))
        report = load_report(report_path)
    return report
