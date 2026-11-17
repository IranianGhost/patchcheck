#!/usr/bin/env bash
# Re-record the readelf evidence used by tests/unit/test_hardening.py.
# Builds targets/tlvparse/base with the project release flags, then with one
# protection removed at a time, and stores `readelf -W -h -l -d -s` exactly as
# build.py runs it. Usage: bash record.sh
set -euo pipefail
cd "$(dirname "$0")"
SRC="$(cd ../../../../targets/tlvparse/base && pwd)"
docker run --rm --platform linux/amd64 --network none -v "$PWD:/out" -v "$SRC:/src:ro" patchcheck-framework:1.0 bash -c '
set -eu
mkdir -p /work && cp /src/tlvparse.c /work/ && cd /work
FULL="-Wall -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -O2"
build() {  # name, flags...
  local name=$1; shift
  gcc "$@" tlvparse.c -o "$name" 2>/dev/null
  readelf -W -h -l -d -s "$name" > "/out/$name.txt"
}
build hardened       $FULL
build execstack      $FULL -Wl,-z,execstack
build no-pie         ${FULL/-fPIE -pie/-fno-pie -no-pie}
build partial-relro  ${FULL/-Wl,-z,relro,-z,now/-Wl,-z,relro,-z,lazy}
build no-relro       ${FULL/-Wl,-z,relro,-z,now/-Wl,-z,norelro,-z,lazy}
build no-canary      ${FULL/-fstack-protector-strong/-fno-stack-protector}
build no-fortify     ${FULL/-D_FORTIFY_SOURCE=2/-U_FORTIFY_SOURCE}
'
ls *.txt
