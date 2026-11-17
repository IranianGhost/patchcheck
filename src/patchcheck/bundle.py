"""Self-contained source/evidence bundles with safe extraction and real rebuild."""
import shutil
import tarfile
import tempfile
from importlib.resources import files
from pathlib import Path

from .contracts import ConfigError
from .pipeline import confirmed_finding_tests, run_pipeline
from .replay import replay_case
from .report import load_report, write_report
from .sandbox import docker
from .source import git, safe_extract
from .store import checked_path, digest, read_json, verify_evidence, write_json


def unpack_bundle(archive_path, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, 'r:gz') as archive:
            members = archive.getmembers()
            if len(members) > 50000 or sum(member.size for member in members) > 4 * 1024**3:
                raise ConfigError('bundle exceeds extraction budget (50000 files / 4 GiB)')
            safe_extract(archive, destination)
    except tarfile.TarError as exc:
        raise ConfigError(f'cannot read reproduction bundle: {exc}') from exc
    manifest = read_json(destination / 'manifest.json')
    if manifest.get('schema_version') != '1.0' or manifest.get('kind') != 'patchcheck-reproduction':
        raise ConfigError('unsupported reproduction bundle format')
    verify_evidence(destination, manifest['files'])
    return manifest


def bundle_test_ids(report):
    ids = set(confirmed_finding_tests(report))
    ids.update(test['id'] for test in report['tests'] if test['signature'])
    if not ids and report['tests']:
        ids.add(report['tests'][0]['id'])
    return ids


def verify_rebuilt_binaries(original, rebuilt):
    fields = ('binary_sha256', 'command', 'flags')
    expected = {build['id']: tuple(build[field] for field in fields) for build in original['builds']}
    actual = {build['id']: tuple(build[field] for field in fields) for build in rebuilt['builds']}
    for build_id in sorted(expected.keys() | actual.keys()):
        if expected.get(build_id) != actual.get(build_id):
            raise ConfigError(f'rebuilt binary hash or build settings differ: {build_id}')


def make_bundle(report_path, destination, *, include_image=True):
    report_path = Path(report_path).resolve()
    root = report_path.parent
    report = load_report(report_path)
    if report['technical_errors']:
        raise ConfigError('a reproducibility bundle requires successful builds and executions')
    selected = bundle_test_ids(report)
    for test_id in sorted(selected):
        if not any(replay['test_id'] == test_id and replay['additional_count_per_cell'] >= 3 for replay in report['replays']):
            replay_case(report_path, test_id, 3)
    report = load_report(report_path)
    destination = Path(destination).resolve()
    if destination.exists():
        raise ConfigError(f'bundle destination already exists: {destination}')
    canonical = root / 'bundles' / destination.name
    canonical.parent.mkdir(exist_ok=True)
    if canonical.exists():
        raise ConfigError(f'bundle already exists: {canonical}')
    with tempfile.TemporaryDirectory(prefix='patchcheck-bundle-') as tmp:
        stage = Path(tmp)
        evidence = stage / 'evidence'
        for reference in (*report['evidence_index'], 'report.json', 'summary.md'):
            source = checked_path(root, reference)
            target = checked_path(evidence, reference)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        captured = dict(report, bundles=[])
        write_json(stage / 'evidence/report.json', captured)
        project = stage / 'project'
        shutil.copytree(Path(__file__).parent, project / 'src/patchcheck', ignore=shutil.ignore_patterns('__pycache__'))
        source_root = Path(__file__).resolve().parents[2]
        for name in ('pyproject.toml', 'requirements.lock'):
            if (source_root / name).is_file():
                shutil.copyfile(source_root / name, project / name)
            else:
                (project / name).write_bytes(files('patchcheck').joinpath('resources/' + name).read_bytes())
        if (source_root / 'vendor/wheels').is_dir():
            shutil.copytree(source_root / 'vendor/wheels', project / 'vendor/wheels')
        environment = stage / 'environment'
        environment.mkdir()
        (environment / 'Dockerfile').write_bytes(files('patchcheck').joinpath('resources/Dockerfile').read_bytes())
        write_json(environment / 'lock.json', report['environment'])
        image_id = report['environment']['image']['id']
        if include_image:
            docker(['image', 'save', '--output', str(environment / 'image.tar'), image_id], timeout=300)
        verdicts = {0: 'PASS', 10: 'VULN_REMAINS / NEW_ISSUE', 20: 'FUNC_REGRESSION',
                    30: 'BUILD_OR_CONFIG_ERROR', 40: 'INCONCLUSIVE'}
        nature = ('The target is a harmless framework fixture, not a security evaluation target.'
                  if report['fixture'] else f"Target: {report['target']} (real evaluation target).")
        readme = f'''# Portable reproduction
{nature}
Use Linux x86_64 with Docker and Python >=3.11.

python3 -m venv .venv
.venv/bin/pip install --no-index --find-links project/vendor/wheels -r project/requirements.lock
PYTHONPATH=project/src .venv/bin/python -m patchcheck reproduce /path/to/this-bundle.tar.gz --out /tmp/patchcheck-rebuilt

Expected exit code: {report['exit_code']} ({verdicts.get(report['exit_code'], '?')}).
The command verifies hashes, loads the exact included image if needed, restores
both exact source trees from the snapshot Git bundle, builds both variants,
runs the full test matrix and executes three additional paired replays.
Reports are under /tmp/patchcheck-rebuilt/result/. No host services are changed.
Source-checkout bundles include checksum-listed dependency wheels for Python
3.11/3.12 Linux x86_64. For a wheel-installed framework without a wheelhouse,
install the same requirements.lock from your normal package index instead.
When image.tar is omitted, the exact captured image must already be present;
environment/Dockerfile uses a digest-pinned base and dated Debian snapshot.
Original commit IDs/dirty manifests and all raw evidence are in evidence/sources.
Historical commands retain their original paths as provenance, but reproduction
rewrites every required source/input/config path to this extracted bundle.
'''
        (stage / 'README.md').write_text(readme)
        manifest = {'schema_version': '1.0', 'kind': 'patchcheck-reproduction', 'target': report['target'],
                    'source_versions': report['versions'], 'image_id': image_id,
                    'image_included': include_image, 'selected_tests': sorted(selected),
                    'files': {str(path.relative_to(stage)): digest(path) for path in sorted(stage.rglob('*'))
                              if path.is_file()}}
        write_json(stage / 'manifest.json', manifest)
        with tarfile.open(canonical, 'w:gz') as archive:
            for path in sorted(stage.rglob('*')):
                if path.is_symlink():
                    raise ConfigError('symlink in bundle material')
                archive.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if canonical != destination:
        shutil.copyfile(canonical, destination)
    report['bundles'].append(str(canonical.relative_to(root)))
    write_report(report, root)
    return destination


def reproduce(bundle_path, out):
    root = Path(out).resolve()
    if root.exists() and any(root.iterdir()):
        raise ConfigError('reproduction output directory must be empty')
    root.mkdir(parents=True, exist_ok=True)
    extracted = root / '.bundle'
    manifest = unpack_bundle(bundle_path, extracted)
    image = manifest['image_id']
    present = docker(['image', 'inspect', image], check=False).returncode == 0
    if not present:
        image_archive = extracted / 'environment/image.tar'
        if not manifest['image_included'] or not image_archive.is_file():
            raise ConfigError('exact image is missing; build the included recipe and verify tool versions, or use a bundle including image.tar')
        docker(['image', 'load', '--input', str(image_archive)], timeout=300)
        docker(['image', 'inspect', image])
    evidence = extracted / 'evidence'
    original = load_report(evidence / 'report.json')
    repo = root / 'restored-source'
    git(root, 'clone', '--quiet', str(evidence / 'sources/snapshots.bundle'), str(repo))
    config = read_json(evidence / original['config'])
    config['source'] = {'repo': str(repo), 'base': 'base', 'candidate': 'candidate'}
    config['environment']['image'] = image
    config['corpus_dir'] = str(root / 'fresh-corpus')
    config['tests'] = []
    for test in original['tests']:
        oracle = None
        if test['oracle'] is not None:
            oracle = checked_path(root, 'reference-oracles/' + test['id'] + '.json')
            write_json(oracle, test['oracle'])
        config['tests'].append({'id': test['id'], 'category': test['category'],
                                'input': str(checked_path(evidence, test['input'])),
                                'sha256': test['sha256'], 'oracle': str(oracle) if oracle else None,
                                'signature': test['signature'], 'input_mode': test['input_mode'],
                                'regression': test['regression'] or {}})
    config_path = root / 'reproduction-config.json'
    write_json(config_path, config)
    # The reproduction run verifies the matrix; it does not nest another round of
    # automatic replays and bundling (followup=False).
    report = run_pipeline(config_path, root / 'result', followup=False)
    if report['technical_errors']:
        return report
    # Source snapshots use new commit IDs. Compare the original file manifests.
    for version in ('base', 'candidate'):
        expected = read_json(evidence / original['versions'][version]['manifest'])
        actual = read_json(root / 'result' / report['versions'][version]['manifest'])
        if expected != actual:
            raise ConfigError(f'reproduced {version} source does not match the captured version')
    verify_rebuilt_binaries(original, report)
    for test_id in manifest['selected_tests']:
        replay_case(root / 'result/report.json', test_id, 3)
    report = load_report(root / 'result/report.json')
    write_json(root / 'original-provenance.json', manifest['source_versions'])
    return report
