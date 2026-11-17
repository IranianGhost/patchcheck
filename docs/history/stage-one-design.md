# Patchcheck stage-one design

The user's implementation request authorizes the supplied, detailed stage-one
specification in `docs/design/stage-one-requirements.fa.md`. This document records
implementation choices, not additional approval requirements.

## Scope and choices

Implement a standalone Python 3.11+ CLI named `patchcheck`, with JSON Schema
2020-12 contracts and JSON configurations. Sources are local Git repositories
with real base/candidate revisions; optional dirty overlays and supplied diffs
are preserved and verified against the exact materialized sources. Each build
uses its own source directory and immutable binary snapshot.

Docker is the isolation boundary. Build and execution run in Linux x86_64
containers using one captured image ID, no network, no published ports, a
non-root UID, dropped capabilities, bounded CPU/memory/PIDs/output and wall
time. Sanitized executions omit RLIMIT_AS because ASan needs a large virtual
address space; cgroup memory remains enforced equally for both revisions.
An internal POSIX worker reports native exit status, signals and rusage before
the outer container status is interpreted. Container OOM and worker failures
are recorded separately. Each operation creates and removes only its own
uniquely named containers. No daemon, firewall, service or existing container
is modified. Server provisioning creates only `/opt/patchcheck-framework` and
an image named `patchcheck-framework`; if Docker is absent, do not install or
restart host software without establishing a non-disruptive alternative.

The alternative, running arbitrary targets directly on a shared host with
ulimits alone, does not supply sufficient filesystem/process isolation.
One container per target run is slower but gives enforceable cgroup limits,
clean process teardown and clear evidence. JSON avoids an extra YAML parser.

## Data and architecture

`contracts.py`: schema loading/validation, path checks and config loading.
`store.py`: atomic JSON, hashes, confined artifact references and evidence index.
`source.py`: exact Git snapshots, dirty-state reproduction, binary-safe diff and hunks.
`sandbox.py` + `worker.py`: constrained Docker lifecycle and native subprocess measurement.
`build.py` + `elf.py`: two revision × two build matrix, compiler/environment and raw ELF evidence.
`oracle.py`: exact/regex/JSON comparison from independently documented oracle files.
`analysis.py`: explicit incomplete analyze/correlate extension points and tri-state signature matching.
`decision.py`: independent axes and precedence 30 > 10 > 20 > 40 > 0.
`pipeline.py`: test/corpus discovery, full execution matrix, replay, report generation.
`minimize.py`: bounded delta debugging and automatic corpus registration only on definite matching.
`bundle.py`: portable source/input/evidence bundles, extraction validation and clean rebuild/replay.
`cli.py`: validate-config/build/run/compare/replay/minimize/report/bundle operations.

Production analysis defaults to unknown. A built-in, explicitly synthetic
marker analyzer is available only for fixture mode, and can never make a
real stage-one run complete. Source fixtures are two harmless C/C++ programs:
binary byte statistics and line parsing. Their independent specifications
define expected outputs, rejection exit codes and safe marker failures.
Signal-only observations do not infer memory bugs. No model calls are used.

## Verification and evidence

Use unittest for unit and Linux/Docker integration tests. Prove all three input
methods and four build cells; oracle truth table; signals/timeouts/CPU/OOM/
output limits/runner error; replay stability; strict signature preservation;
generated regression reload; portable bundle rebuild; dirty sources;
malformed config/report; complete evidence references and exit-code precedence.
The phase-one pipeline exits 40 on expected missing specialist analysis,
30 on infrastructure/configuration errors. CI keeps the real CLI code while
uploading artifacts and separately reports framework smoke-test success.

Final handoff includes acceptance evidence, architecture, CLI/schema mapping,
teacher proposal with approval explicitly pending, a four-person contribution
ledger with human names/contributions unclaimed, and precise phase-two APIs.
