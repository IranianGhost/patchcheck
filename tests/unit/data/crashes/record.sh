#!/usr/bin/env bash
# Re-record the real diagnostics used by tests/unit/test_analysis.py.
# Runs inside the project toolchain image; writes <sample>.txt (stderr) and
# samples.json (how each process terminated). Usage: bash record.sh
set -euo pipefail
cd "$(dirname "$0")"
docker run --rm --platform linux/amd64 --network none -v "$PWD:/out" patchcheck-framework:1.0 bash -c '
set -u
mkdir -p /work && cp /out/crashzoo.c /out/crashzoo.cpp /work/ && cd /work
SAN="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
REL="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2"
gcc $SAN crashzoo.c -o san && g++ $SAN crashzoo.cpp -o sancpp && gcc $REL crashzoo.c -o rel
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
results=""
run() {  # name, command...
  local name=$1; shift
  "$@" > /dev/null 2> "/out/$name.txt"; local status=$?
  results="$results\"$name\": $status, "
}
run asan-heap ./san heap;     run asan-stack ./san stackp;  run asan-uaf ./san uaf
run asan-double ./san double; run asan-global ./san global; run asan-cpp ./sancpp
run ubsan-null ./san null;    run ubsan-div ./san div;      run ubsan-index ./san index
run ubsan-objsize ./san stack
run release-heap ./rel heap;  run release-stack ./rel stack; run release-double ./rel double
run release-null ./rel null;  run release-div ./rel div
echo "{${results%, }}" > /out/samples.json
'
cat samples.json
