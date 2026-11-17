"""Bounded Docker lifecycle. Never alter containers outside this invocation."""
import base64
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .contracts import ConfigError


def docker(args, timeout=30, check=True):
    try:
        p = subprocess.run(['docker', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigError(f'Docker environment error: {exc}') from exc
    if check and p.returncode:
        raise ConfigError(f'docker {args[0]} failed: {p.stderr.decode(errors="replace")}')
    return p


def inspect_image(image):
    """Inspect a Docker image by name, falling back to a repository-tag listing.

    Docker Desktop on macOS occasionally fails a name-based `image inspect` with
    "No such image" even though `docker images` lists it; inspecting the resolved
    ID is stable. The pipeline normally passes a pre-resolved `image_info`, so this
    fallback only runs when the image is first resolved from a name.
    """
    result = docker(['image', 'inspect', image], check=False)
    if result.returncode == 0:
        return json.loads(result.stdout)[0]
    listing = docker(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}\t{{.ID}}'])
    for line in listing.stdout.decode('utf-8', errors='replace').splitlines():
        parts = line.split('\t')
        if len(parts) == 2 and parts[0] == image:
            return json.loads(docker(['image', 'inspect', parts[1]]).stdout)[0]
    raise ConfigError(f'image not found: {image}')


class Sandbox:
    def __init__(self, image, limits, *, image_info=None):
        self.limits = dict(limits)
        if image_info is None:
            info = inspect_image(image)
            if info['Os'] != 'linux' or info['Architecture'] != 'amd64':
                raise ConfigError(f'image must be Linux amd64, got {info["Os"]}/{info["Architecture"]}')
            image_info = {'id': info['Id'], 'repo_digests': info.get('RepoDigests', []),
                          'requested': image, 'architecture': info['Architecture'], 'os': info['Os']}
        self.image_info = image_info
        self.image = image_info['id']

    def execute(self, command, workdir, *, env=None, stdin=None, mounts=None, writable=False, build=False):
        # Stage only this invocation under /tmp. This also works with Docker
        # Desktop when Documents is protected by macOS filesystem permissions.
        with tempfile.TemporaryDirectory(prefix='patchcheck-sandbox-', dir='/tmp') as tmp:
            stage = Path(tmp)
            staged_work = stage / 'work'
            shutil.copytree(workdir, staged_work)
            staged_work.chmod(0o755)
            for item in staged_work.rglob('*'):
                if item.is_symlink():
                    raise ConfigError(f'symlink in sandbox material: {item}')
                item.chmod(item.stat().st_mode | (0o055 if item.is_dir() else 0o044))
            staged_worker = stage / 'worker.py'
            shutil.copyfile(Path(__file__).with_name('worker.py'), staged_worker)
            staged_input = None
            if stdin is not None:
                staged_input = stage / 'input'
                shutil.copyfile(stdin, staged_input)
                staged_input.chmod(0o444)
            staged_mounts = []
            for index, (source, dest) in enumerate(mounts or []):
                target = stage / f'mount-{index}'
                source = Path(source)
                if source.is_dir():
                    shutil.copytree(source, target)
                else:
                    shutil.copyfile(source, target)
                    target.chmod(source.stat().st_mode | 0o044)
                staged_mounts.append((target, dest))
            try:
                return self._execute(command, staged_work, staged_worker, env=env, stdin=staged_input,
                                     mounts=staged_mounts, writable=writable, build=build)
            finally:
                if writable:
                    for item in staged_work.rglob('*'):
                        if item.is_symlink():
                            raise ConfigError('build produced an unsupported symlink')
                    shutil.copytree(staged_work, workdir, dirs_exist_ok=True)

    def _execute(self, command, workdir, worker, *, env=None, stdin=None, mounts=None, writable=False, build=False):
        workdir = Path(workdir).resolve()
        if not workdir.is_dir():
            raise ConfigError(f'sandbox cwd does not exist: {workdir}')
        name = 'patchcheck-' + uuid.uuid4().hex
        limits = dict(self.limits)
        if build:
            limits['wall_seconds'] = limits['build_wall_seconds']
            limits['cpu_seconds'] = min(60, max(limits['cpu_seconds'], 30))
        # Writable builds use the caller's file UID (root callers chown only their
        # newly copied build directory). All executions use an unprivileged UID.
        uid = os.getuid() if writable and os.getuid() != 0 else 65534
        gid = os.getgid() if writable and os.getuid() != 0 else 65534
        if writable and os.getuid() == 0:
            for item in [workdir, *workdir.rglob('*')]:
                if item.is_symlink():
                    raise ConfigError('symlink in writable sandbox')
                os.chown(item, uid, gid)
        for component in (workdir, *workdir.parents):
            # Do not modify host parents: bind-mount root permissions are all
            # that matter inside the namespace.
            if component == workdir and not writable:
                workdir.chmod(workdir.stat().st_mode | 0o055)
        effective_env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                         'TZ': 'UTC', 'HOME': '/tmp', **(env or {})}
        packet = {'command': list(command), 'cwd': '/work', 'env': effective_env, 'limits': limits,
                  'uid': uid, 'gid': gid, 'has_stdin': stdin is not None}
        encoded = base64.b64encode(json.dumps(packet).encode()).decode()
        args = ['create', '--name', name, '--label', 'org.patchcheck.owner=' + name,
                '--platform', 'linux/amd64', '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
                '--security-opt', 'no-new-privileges:true', '--pids-limit', str(limits['pids']),
                '--memory', f'{limits["memory_mb"]}m', '--memory-swap', f'{limits["memory_mb"]}m',
                '--cpus', '0.5', '--ulimit', 'core=0:0', '--stop-timeout', '1',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,mode=1777',
                '--mount', f'type=bind,src={workdir},dst=/work' + ('' if writable else ',readonly'),
                '--mount', f'type=bind,src={worker.resolve()},dst=/worker.py,readonly']
        if stdin is not None:
            args += ['--mount', f'type=bind,src={Path(stdin).resolve()},dst=/input,readonly']
        for source, dest in (mounts or []):
            if ',' in str(source) or ',' in dest:
                raise ConfigError('comma is not supported in Docker bind paths')
            args += ['--mount', f'type=bind,src={Path(source).resolve()},dst={dest},readonly']
        args += ['--entrypoint', 'python3', self.image, '/worker.py', encoded]
        inspect = {}
        created = False
        try:
            docker(args)
            created = True
            wall_start = time.monotonic()
            # The attach timeout must cover the target's wall limit plus generous
            # attach/startup overhead; Docker Desktop on macOS under emulation can
            # take well over the previous 15-second buffer before streaming output.
            completed = docker(['start', '--attach', name], timeout=max(90, limits['wall_seconds'] + 30), check=False)
            inspect = json.loads(docker(['inspect', name]).stdout)[0]
            try:
                result = json.loads(completed.stdout)
            except (ValueError, UnicodeDecodeError):
                result = {'exit_code': None, 'signal': None, 'timeout': False, 'resource_status': 'unknown',
                          'output_truncated': True, 'runner_error': 'measurement worker did not return valid JSON',
                          'stdout_base64': '', 'stderr_base64': '', 'duration_seconds': time.monotonic() - wall_start,
                          'rusage': {}}
            if inspect['State'].get('OOMKilled'):
                result.update(resource_status='memory_limit', runner_error=None)
            result['stdout_bytes'] = base64.b64decode(result.pop('stdout_base64'))
            result['stderr_bytes'] = base64.b64decode(result.pop('stderr_base64'))
            result['effective_env'] = effective_env
            result['effective_limits'] = limits
            result['sandbox'] = {'name': name, 'image': self.image_info, 'state': inspect['State'],
                                 'host_config': {k: inspect['HostConfig'].get(k) for k in
                                                 ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit',
                                                  'NetworkMode', 'ReadonlyRootfs', 'CapDrop', 'CapAdd', 'SecurityOpt')},
                                 'host_platform': platform.platform(), 'target_uid': uid,
                                 'native_status_channel': 'root-worker-only stdout; child pipes captured separately'}
            return result
        finally:
            if created:
                docker(['rm', '--force', name], check=False)
