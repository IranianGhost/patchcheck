# Locked dependency wheels

These upstream wheels support CPython 3.11/3.12 Linux x86_64 and CPython 3.14
macOS arm64. Pure-Python wheels are shared. SHA256SUMS.json records the exact
bytes checked by ci/bootstrap.py before offline installation. The runtime pins
are in requirements.lock; setuptools 75.8.0 and wheel 0.45.1 are build tools.

Downloaded from the Tsinghua PyPI mirror because this network timed out against
pypi.org. No package contents were modified. Wheel metadata includes upstream
licenses and provenance. To refresh deliberately, use pip download with the
appropriate --platform/--python-version/--only-binary parameters, review versions,
regenerate the checksum manifest, and run clean-install plus full tests.
