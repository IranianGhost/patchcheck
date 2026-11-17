# Portable reproduction
Target: tlvparse (real evaluation target).
Use Linux x86_64 with Docker and Python >=3.11.

python3 -m venv .venv
.venv/bin/pip install --no-index --find-links project/vendor/wheels -r project/requirements.lock
PYTHONPATH=project/src .venv/bin/python -m patchcheck reproduce /path/to/this-bundle.tar.gz --out /tmp/patchcheck-rebuilt

Expected exit code: 10 (VULN_REMAINS / NEW_ISSUE).
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
