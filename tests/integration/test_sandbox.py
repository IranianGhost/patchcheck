import os
import signal
import tempfile
import unittest
from pathlib import Path

from patchcheck.sandbox import Sandbox


LIMITS = {'wall_seconds': 1, 'cpu_seconds': 1,
          'memory_mb': int(os.environ.get('PATCHCHECK_TEST_MEMORY_MB', '128')), 'pids': 16,
          'output_bytes': 4096, 'file_bytes': 1048576, 'build_wall_seconds': 30}


@unittest.skipUnless(os.environ.get('PATCHCHECK_INTEGRATION') == '1', 'set PATCHCHECK_INTEGRATION=1 for real Docker tests')
class SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.box = Sandbox(os.environ.get('PATCHCHECK_IMAGE', 'patchcheck-framework:1.0'), LIMITS)

    def execute(self, code, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            return self.box.execute(['python3', '-c', code], Path(tmp), **kwargs)

    def test_binary_stdout_and_stderr_and_nonzero(self):
        r = self.execute('import os;os.write(1,b"\\x00\\xff");os.write(2,b"err");raise SystemExit(7)')
        self.assertEqual(r['stdout_bytes'], b'\0\xff')
        self.assertEqual(r['stderr_bytes'], b'err')
        self.assertEqual(r['exit_code'], 7)
        self.assertIsNone(r['signal'])
        self.assertFalse(r['timeout'])

    def test_signal_is_native_not_128_plus_signal(self):
        r = self.execute('import os,signal;os.kill(os.getpid(),signal.SIGTERM)')
        self.assertIsNone(r['exit_code'])
        self.assertEqual(r['signal'], signal.SIGTERM)

    def test_timeout_and_output_limit_are_distinct(self):
        r = self.execute('import time;time.sleep(5)')
        self.assertTrue(r['timeout'])
        r = self.execute('import os;os.write(1,b"x"*20000)')
        self.assertEqual(r['resource_status'], 'output_limit')
        self.assertTrue(r['output_truncated'])
        self.assertLessEqual(len(r['stdout_bytes']), 4096)

    def test_missing_executable_is_runner_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.box.execute(['/does-not-exist'], Path(tmp))
        self.assertIsNotNone(r['runner_error'])
        self.assertIsNone(r['exit_code'])

    def test_cpu_limit_is_applied(self):
        box = Sandbox(self.box.image, {**LIMITS, 'wall_seconds': 6})
        with tempfile.TemporaryDirectory() as tmp:
            r = box.execute(['python3', '-c', 'while True: pass'], Path(tmp))
        self.assertEqual(r['resource_status'], 'cpu_limit')
        self.assertFalse(r['timeout'])

    def test_ignored_soft_cpu_signal_still_reports_hard_resource_limit(self):
        box = Sandbox(self.box.image, {**LIMITS, 'wall_seconds': 9})
        with tempfile.TemporaryDirectory() as tmp:
            r = box.execute(['python3', '-c', 'import signal;signal.signal(signal.SIGXCPU,signal.SIG_IGN)\nwhile True:pass'], Path(tmp))
        self.assertEqual(r['signal'], signal.SIGKILL)
        self.assertEqual(r['resource_status'], 'cpu_limit')
        self.assertFalse(r['timeout'])

    def test_real_flaky_output_is_unstable(self):
        import hashlib
        from patchcheck.replay import stability
        records = []
        for _ in range(3):
            r = self.execute('import os;print(os.urandom(16).hex())')
            r['stdout_sha256'] = hashlib.sha256(r['stdout_bytes']).hexdigest()
            r['stderr_sha256'] = hashlib.sha256(r['stderr_bytes']).hexdigest()
            records.append(r)
        self.assertEqual(stability(records)['status'], 'unstable')

    def test_pids_and_file_size_caps_are_applied_and_children_are_cleaned(self):
        code = '''import os,errno,time
children=[]
try:
 for _ in range(100):
  pid=os.fork()
  if not pid:time.sleep(20);os._exit(0)
  children.append(pid)
except OSError as e:
 print('limited' if e.errno==errno.EAGAIN else 'unexpected',flush=True)
'''
        result = self.execute(code)
        self.assertIn(b'limited', result['stdout_bytes'])
        result = self.execute('import signal;signal.signal(signal.SIGXFSZ,signal.SIG_DFL);open("/tmp/big","wb").write(b"x"*3000000)')
        self.assertEqual(result['resource_status'], 'file_limit')

    def test_container_is_nonroot_no_network_and_memory_is_bounded(self):
        r = self.execute('import os;print(os.getuid());print(open("/proc/net/route").read().count("eth0"))')
        self.assertEqual(r['stdout_bytes'], b'65534\n0\n')
        box = Sandbox(self.box.image, {**LIMITS, 'wall_seconds': 6})
        with tempfile.TemporaryDirectory() as tmp:
            r = box.execute(['python3', '-c', 'a=[]\nwhile True:a.append(bytearray(8*1024*1024))'], Path(tmp))
        self.assertEqual(r['resource_status'], 'memory_limit')
