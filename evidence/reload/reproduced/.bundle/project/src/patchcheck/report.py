"""Schema-validated reports whose artifact references must resolve and match."""
from pathlib import Path

from .contracts import ConfigError, validate
from .store import checked_path, digest, evidence_index, read_json, verify_evidence, write_json


def verify_references(report, root):
    refs = [report['config']]
    if report['diff'].get('path'):
        refs.append(report['diff']['path'])
    for build in report['builds']:
        refs += [build['stdout'], build['stderr'], *build['evidence']]
        if build['binary']:
            refs.append(build['binary'])
        if build['hardening'].get('raw'):
            refs.append(build['hardening']['raw'])
    for test in report['tests']:
        refs.append(test['input'])
    for run in report['runs']:
        refs += [run['stdout'], run['stderr'], run['input'], *run['diagnostics'], *run['trace']]
    for finding in report['findings']:
        refs += finding['evidence']
    for cov_run in (report['diff'].get('coverage') or {}).get('runs', []):
        refs += cov_run.get('evidence', [])
    for ref in refs:
        if not checked_path(root, ref).is_file():
            raise ConfigError(f'report references missing evidence: {ref}')


def write_report(report, root):
    root = Path(root)
    verify_references(report, root)
    report['evidence_index'] = evidence_index(root)
    validate('FinalReport', report)
    write_json(root / 'report.json', report)
    axes = report['axes']
    versions = report.get('versions', {})
    refs = ' → '.join(f'{v} `{versions[v].get("commit", "?")[:10]}`' for v in ('base', 'candidate') if v in versions)
    summary = [f'# Patchcheck: {report["target"]}', '',
               f'**Verdict: {report["exit_code"]} {VERDICTS[report["exit_code"]]}**' + (' (fixture target)' if report['fixture'] else ''),
               '', f'Versions: {refs or "-"}',
               f'Builds: {len(report["builds"])}; tests: {len(report["tests"])}; executions: {len(report["runs"])}.',
               '', '| Axis | Result |', '|---|---|',
               f'| Security | {axes["security"]["status"]} (target reproduced on base: '
               f'{"yes" if axes["security"]["baseline_reproduced"] else "no"}) |',
               f'| Functional | {axes["functional"]["status"]} |',
               f'| Analysis complete | {"yes" if axes["completeness"]["complete"] else "no"} |',
               '', *finding_table(report['findings']),
               '', *relation_table(report.get('patch_relations', []), report['findings']),
               '', *hardening_table(report.get('hardening', {})),
               '', '## Why the analysis is not complete', '',
               *(['- ' + x for x in axes['completeness']['reasons']] or ['- (complete)']),
               '', '## Technical errors', '', *(['- ' + x for x in report['technical_errors']] or ['- none']),
               '', '## Known limitations', '', *['- ' + x for x in report['unknowns']],
               '', '## Functional comparisons', '',
               '| Test | Build | Base oracle | Candidate oracle | Comparison |', '|---|---|---|---|---|']
    for pair in report['axes']['functional'].get('comparisons', []):
        summary.append(f'| {pair["test_id"]} | {pair["build_type"]} | {pair["base"]} | {pair["candidate"]} | {pair["status"]} |')
    summary += ['', *crash_table(report['runs'])]
    (root / 'summary.md').write_text('\n'.join(summary) + '\n')


VERDICTS = {0: 'PASS', 10: 'VULN_REMAINS / NEW_ISSUE', 20: 'FUNC_REGRESSION',
            30: 'BUILD_OR_CONFIG_ERROR', 40: 'INCONCLUSIVE'}


def finding_table(findings):
    if not findings:
        return ['## Findings', '', 'No findings.']
    rows = [f'| {f["status"]} | {f["error_type"]} | {f["detection_method"]} | {(f["location"] or "-").replace("|", "/")} | '
            f'{f["confirmation"]} | {f["replay_stability"]} | {f["id"]} |' for f in findings]
    return ['## Findings', '', '| Status | Error type | Detection | Location | Evidence | Replay | Id |',
            '|---|---|---|---|---|---|---|', *rows]


def hardening_table(hardening):
    if hardening.get('comparison') != 'compared':
        return ['## Binary hardening (release builds)', '', f'Not compared: {hardening.get("comparison", "-")}.']
    rows = [f'| {name} | {hardening["base"][name]} | {hardening["candidate"][name]} | {hardening["changes"][name]} |'
            for name in hardening['changes']]
    notes = [f'- **degraded:** {d}' for d in hardening['degraded']] + [f'- warning: {w}' for w in hardening['warnings']]
    return ['## Binary hardening (release builds)', '', '| Protection | Base | Candidate | Change |',
            '|---|---|---|---|', *rows, *([''] + notes if notes else [])]


def relation_table(relations, findings):
    if not relations:
        return ['## Patch correlation', '', 'No findings to correlate.']
    status = {f['id']: f['status'] for f in findings}
    rows = [f'| {r["finding_id"]} | {status.get(r["finding_id"], "-")} | **{r["relation"]}** | '
            f'{", ".join(r["hunk_ids"]) or "-"} | {"; ".join(r["evidence"]).replace("|", "/")} |' for r in relations]
    return ['## Patch correlation', '',
            'confirmed = a changed function is on the failing stack; rejected = the failure persists and the '
            'patch does not touch its stack; unknown = not enough evidence.', '',
            '| Finding | Status | Relation | Hunks | Evidence |', '|---|---|---|---|---|', *rows]


def describe_termination(term):
    if term['kind'] == 'signal':
        return term['signal_name']
    if term['kind'] == 'exit':
        return f'exit {term["exit_code"]}'
    return term['kind']


def crash_table(runs):
    """One row per abnormal run (original executions only), from analysis observations."""
    rows = []
    for run in runs:
        if run['replay_of'] is not None:
            continue
        for obs in run['analysis'].get('observations', []):
            if 'termination' not in obs:
                continue
            loc = obs['location']
            where = f'{loc["file"]}:{loc["line"]} in {loc["function"]}' if loc and loc.get('function') else \
                f'{loc["file"]}:{loc["line"]}' if loc else '-'
            access = f'{obs["access"]["kind"]} {obs["access"]["size"] or ""}'.strip() if obs['access'] else '-'
            rows.append(f'| {run["test_id"]} | {run["version"]} | {run["build_type"]} | {obs["error_type"]} | '
                        f'{obs["detection_method"]} | {describe_termination(obs["termination"])} | {access} | '
                        f'{where.replace("|", "/")} | {obs["confirmation"]} |')
    if not rows:
        return ['## Crash classification', '', 'No abnormal termination was observed.']
    return ['## Crash classification', '',
            '| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |',
            '|---|---|---|---|---|---|---|---|---|', *rows]


def verify_coverage_evidence(report, root):
    """Every referenced coverage file must exist, be listed in evidence_index and
    match its recorded hash, so a coverage witness cannot be swapped or referenced
    without a hash."""
    index = report.get('evidence_index') or {}
    for cov_run in (report.get('diff', {}).get('coverage') or {}).get('runs', []):
        for ref in cov_run.get('evidence', []):
            path = checked_path(root, ref)
            if not path.is_file():
                raise ConfigError(f'coverage evidence missing: {ref}')
            if ref not in index:
                raise ConfigError(f'coverage evidence is not in evidence_index: {ref}')
            if digest(path) != index[ref]:
                raise ConfigError(f'coverage evidence hash mismatch: {ref}')


def load_report(path):
    path = Path(path).resolve()
    report = read_json(path)
    validate('FinalReport', report)
    verify_references(report, path.parent)
    verify_evidence(path.parent, report['evidence_index'])
    verify_coverage_evidence(report, path.parent)
    return report
