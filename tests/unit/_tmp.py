"""Sandbox-tolerant temporary directories for unit tests.

Python's ``tempfile.TemporaryDirectory`` creates the directory with mode 0o700.
Restricted sandboxes that honour POSIX mode bits (and some CI containers with a
tight umask/ACL) can then deny writes from the very process that created the
directory. These helpers create a permissive directory under the system temp
root instead, which behaves identically on normal Linux/Windows while also
working inside such sandboxes. Test-only; never imported by production code.
"""
import contextlib
import shutil
import tempfile
import uuid
from pathlib import Path


def mktempdir():
    """Return a fresh permissive temporary directory (caller cleans up)."""
    path = Path(tempfile.gettempdir()) / ('patchcheck-' + uuid.uuid4().hex)
    path.mkdir(mode=0o777, parents=True)
    return path


@contextlib.contextmanager
def tmpdir():
    """Context manager yielding a permissive temporary directory, auto-removed."""
    path = mktempdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
