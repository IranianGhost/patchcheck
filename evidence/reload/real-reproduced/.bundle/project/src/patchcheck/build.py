"""Independent materialized source trees, toolchain probes and four-cell builds."""
import json
import re
import shutil
import sys
from pathlib import Path

from .contracts import ConfigError, validate
from .elf import check_elf, instrumentation_markers, raw_hardening
from .sandbox import Sandbox
from .source import copy_source, snapshot_versions
from .store import digest, write_json


def capture(folder, result):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'stdout.bin').write_bytes(result.pop('stdout_bytes'))
    (folder / 'stderr.bin').write_bytes(result.pop('stderr_bytes'))
    write_json(folder / 'measurement.json', result)


def probe_environment(config, root, box):
    folder = root / 'environment'
    folder.mkdir()
    code = '''import json,platform,subprocess,pathlib
tools={}
for tool in TOOLS:
 try:
  p=subprocess.run([tool,'--version'],capture_output=True,timeout=5)
  tools[tool]={'returncode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
 except Exception as e: tools[tool]={'error':str(e)}
print(json.dumps({'system':platform.system(),'machine':platform.machine(),'python':platform.python_version(),
 'os_release':pathlib.Path('/etc/os-release').read_text(),'tools':tools,
 'packages':pathlib.Path('/opt/patchcheck-packages.lock').read_text() if pathlib.Path('/opt/patchcheck-packages.lock').exists() else 'unavailable'}))
'''.replace('TOOLS', repr(sorted(config['tools'])))
    # Setup step, not a target execution: use build time limits so a slow or
    # emulated host is not misreported as a broken environment.
    result = box.execute(['python3', '-c', code], folder, build=True)
    raw = result['stdout_bytes']
    capture(folder, result)
    try:
        probe = json.loads(raw)
    except ValueError as exc:
        raise ConfigError('environment probe did not return valid evidence') from exc
    if probe['system'] != 'Linux' or probe['machine'] != 'x86_64':
        raise ConfigError(f'target environment must be Linux x86_64: {probe}')
    for tool, pattern in config['tools'].items():
        info = probe['tools'][tool]
        if info.get('error') or info.get('returncode') != 0 or not re.search(pattern, info.get('stdout', '')):
            raise ConfigError(f'required tool/version mismatch: {tool}: {info}')
    probe['image'] = box.image_info
    probe['orchestrator'] = {'python': sys.version, 'platform': sys.platform}
    write_json(folder / 'environment.json', probe)
    return probe


def build_all(config, out, config_root=None):
    root = Path(out).resolve()
    config_root = Path(config_root or '.')
    versions = snapshot_versions(config, root, config_root)
    box = Sandbox(config['environment']['image'], config['limits'])
    environment = probe_environment(config, root, box)
    records = []
    for version in ('base', 'candidate'):
        for kind in ('release', 'sanitized'):
            spec = config['builds'][kind]
            folder = root / 'builds' / version / kind
            work = folder / 'work'
            copy_source(root / versions[version]['path'], work)
            command = []
            for argument in spec['command']:
                command.extend(spec['flags'] if argument == '{flags}' else
                               [spec['compiler'] if argument == '{compiler}' else argument])
            result = box.execute(command, work, env=config['environment']['variables'], writable=True, build=True)
            succeeded = result['exit_code'] == 0 and not result['runner_error'] and not result['timeout'] and result['resource_status'] == 'ok'
            error = None if succeeded else f'build failed: exit={result["exit_code"]}, signal={result["signal"]}, resource={result["resource_status"]}, runner={result["runner_error"]}'
            capture(folder, result)
            binary = folder / 'program.elf'
            hardening = {'extraction_complete': False, 'interpretation': 'unknown'}
            elf = {'architecture': 'unknown', 'file_type': 'unknown'}
            if succeeded:
                output = work / spec['binary']
                try:
                    if output.is_symlink() or not output.resolve().is_relative_to(work.resolve()):
                        raise ConfigError('binary output escapes build directory')
                    elf = check_elf(output)
                    shutil.copy2(output, binary)
                    evidence = box.execute(['readelf', '-W', '-h', '-l', '-d', '-s', '/binary'], work,
                                           mounts=[(binary, '/binary')], build=True)
                    raw = evidence['stdout_bytes']
                    ok = evidence['exit_code'] == 0 and not evidence['output_truncated'] and not evidence['runner_error']
                    capture(folder / 'elf', evidence)
                    if not ok:
                        raise ConfigError('readelf failed or evidence was truncated')
                    hardening = raw_hardening(raw.decode('utf-8', errors='replace'))
                    hardening['raw'] = str((folder / 'elf/stdout.bin').relative_to(root))
                    readelf_info = environment['tools'].get('readelf')
                    if not readelf_info or not readelf_info.get('stdout'):
                        raise ConfigError('readelf is required for hardening evidence')
                    hardening['tool_version'] = readelf_info['stdout']
                    if kind == 'sanitized':
                        # A sanitized cell must actually be instrumented, otherwise a
                        # full copy of the release spec would be accepted as sanitized.
                        markers = instrumentation_markers(raw.decode('utf-8', errors='replace'))
                        required = spec.get('instrumentation') or []
                        missing = [m for m in required if m not in markers['symbols']]
                        if not required and not any(markers[k] for k in ('asan', 'ubsan', 'tsan', 'msan')):
                            missing = ['any sanitizer runtime (ASan/UBSan)']
                        if missing:
                            raise ConfigError(f'sanitized build has no instrumentation evidence: missing {missing}; '
                                              f'add -fsanitize to the build and declare builds.sanitized.instrumentation')
                        hardening['instrumentation'] = markers
                except (ConfigError, OSError) as exc:
                    succeeded, error = False, str(exc)
            record = {'schema_version': '1.0', 'id': f'{version}-{kind}', 'version': version,
                      'build_type': kind, 'commit': versions[version]['commit'], 'source': versions[version],
                      'binary': str(binary.relative_to(root)) if binary.exists() else None,
                      'binary_sha256': digest(binary) if binary.exists() else None,
                      'architecture': elf['architecture'], 'file_type': elf['file_type'],
                      'compiler': environment['tools'].get(spec['compiler'], {'error': 'compiler not declared in tools'}),
                      'flags': spec['flags'], 'command': command, 'environment': environment,
                      'result': 'success' if succeeded else 'failed', 'error': error,
                      'stdout': str((folder / 'stdout.bin').relative_to(root)),
                      'stderr': str((folder / 'stderr.bin').relative_to(root)), 'hardening': hardening,
                      'evidence': [str((folder / 'measurement.json').relative_to(root))]}
            validate('BuildRecord', record)
            write_json(folder / 'build.json', record)
            records.append(record)
    write_json(root / 'builds.json', records)
    return records, versions, environment
