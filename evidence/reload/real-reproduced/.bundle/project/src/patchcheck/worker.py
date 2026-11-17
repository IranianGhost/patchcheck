"""Standalone trusted measurement worker inside a disposable Linux container.

Only this root worker owns the control stdout pipe. Target stdout/stderr are
separate anonymous pipes. The child drops UID/GID/capabilities before exec.
No status file or Docker socket is exposed to the target.
"""
import base64
import json
import os
import resource
import selectors
import signal
import subprocess
import sys
import time


def execute(spec):
    limits = spec['limits']
    start = time.monotonic()
    result = {'exit_code': None, 'signal': None, 'timeout': False, 'resource_status': 'ok',
              'output_truncated': False, 'runner_error': None, 'rusage': {}}
    captured = {'stdout': bytearray(), 'stderr': bytearray()}

    def prepare():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (limits['cpu_seconds'], limits['cpu_seconds'] + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits['file_bytes'], limits['file_bytes']))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        os.setgroups([])
        os.setgid(spec['gid'])
        os.setuid(spec['uid'])

    def stop():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        input_stream = open('/input', 'rb') if spec.get('has_stdin') else open('/dev/null', 'rb')
        with input_stream:
            process = subprocess.Popen(spec['command'], cwd=spec['cwd'], env=spec['env'], stdin=input_stream,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, preexec_fn=prepare, close_fds=True)
            selector = selectors.DefaultSelector()
            for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            status, usage = None, None
            while selector.get_map() or status is None:
                if time.monotonic() - start > limits['wall_seconds']:
                    result['timeout'] = True
                    stop()
                for key, _ in selector.select(0.02):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    buffer = captured[key.data]
                    available = limits['output_bytes'] - len(buffer)
                    buffer.extend(block[:available])
                    if len(block) > available:
                        result['output_truncated'] = True
                        result['resource_status'] = 'output_limit'
                        stop()
                if status is None:
                    pid, child_status, child_usage = os.wait4(process.pid, os.WNOHANG)
                    if pid:
                        status, usage = child_status, child_usage
                        process.returncode = os.waitstatus_to_exitcode(status)
                        stop()  # Clean grandchildren even after the direct child exited.
                if status is not None and time.monotonic() - start > limits['wall_seconds'] + 1:
                    # A descendant may have escaped the process group holding a pipe.
                    result['timeout'] = True
                    break
            selector.close()
            if os.WIFSIGNALED(status):
                result['signal'] = os.WTERMSIG(status)
                if result['signal'] == signal.SIGXCPU:
                    result['resource_status'] = 'cpu_limit'
                elif result['signal'] == signal.SIGXFSZ:
                    result['resource_status'] = 'file_limit'
            else:
                result['exit_code'] = os.WEXITSTATUS(status)
            result['rusage'] = {'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                                'max_rss_kb': usage.ru_maxrss, 'minor_faults': usage.ru_minflt,
                                'major_faults': usage.ru_majflt}
            hard_cpu_seconds = limits['cpu_seconds'] + 1
            if (result['signal'] == signal.SIGKILL and not result['timeout']
                    and result['resource_status'] == 'ok'
                    and usage.ru_utime + usage.ru_stime >= hard_cpu_seconds - 0.2):
                result['resource_status'] = 'cpu_limit'
                result['rusage']['resource_inference'] = 'SIGKILL with measured CPU time at the configured hard RLIMIT_CPU'
    except Exception as exc:
        result['runner_error'] = f'{type(exc).__name__}: {exc}'
    result['duration_seconds'] = time.monotonic() - start
    for name, buffer in captured.items():
        result[name + '_base64'] = base64.b64encode(buffer).decode('ascii')
    return result


if __name__ == '__main__':
    spec = json.loads(base64.b64decode(sys.argv[1]))
    print(json.dumps(execute(spec), sort_keys=True), flush=True)
