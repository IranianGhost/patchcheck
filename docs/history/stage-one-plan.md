# Patchcheck Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and verify all stage-one framework requirements with harmless fixtures.

**Architecture:** Python CLI with JSON Schema contracts and Docker Linux x86_64
build/run isolation. Every result references immutable raw artifacts; specialist
analysis is explicitly incomplete and phase-one comparisons cannot return PASS.

**Tech Stack:** Python 3.11+, jsonschema 4.23.0, unittest, Docker, GCC/G++, binutils, Git.

**Spec:** `docs/design/stage-one-requirements.fa.md`; implementation choices in
`docs/superpowers/specs/2026-11-10-patchcheck-design.md`.

## Global Constraints

- Target: Linux x86_64 ELF C/C++; real Release and Sanitized builds for both revisions.
- Exit precedence: `30 > 10 > 20 > 40 > 0`; stage-one real execution is 40 or technical 30.
- Preserve binary input/stdout/stderr; no shell interpolation of target arguments.
- Replay at least three times; minimization accepts only `match` of the same signature.
- Shared server: no existing service/container/firewall changes; no exposed ports.

## Review Focus

- Invalid paths, symlink escapes, untrusted bundle paths: fail with 30 before writing outside owned paths (tasks 1, 2, 5).
- Dirty or non-UTF8 sources and inputs: exact source/input hashes survive bundles (tasks 2, 5).
- Sanitizer address space, resource kills and leftover grandchildren: preserve native status without inferring vulnerability (tasks 2, 3).
- Flaky output and missing evidence/oracle: no conclusive result, no silently successful serialization (tasks 3, 4, 5).
- Resource or iteration exhaustion during minimization: no invalid regression registration (task 5).

### Task 1: Contracts, evidence, oracle and decision engine

**Files:** `pyproject.toml`, `schemas/*.json`, `src/patchcheck/{contracts,store,oracle,decision,analysis}.py`, `tests/unit/test_contracts.py`, `tests/unit/test_logic.py`.

**Interfaces:** `load_config(path) -> dict`; `validate(kind, value) -> None`;
`evaluate_oracle(run, oracle, root) -> dict`; `decide(axes) -> int`;
`analyze(run, index) -> dict`; `match_failure(expected, observed) -> str`;
`correlate(diff, findings, paired_runs) -> list`.

- [ ] Write failing tests for malformed configs, binary evidence, oracle truth table, tri-state matching and every exit-code combination; run `python -m unittest discover -s tests/unit -v` and observe missing implementation.
- [ ] Implement schema validation, stable paths/hashes, independent oracle, conservative analysis and deterministic decisions.
- [ ] Run unit tests: all pass; commit task.

### Task 2: Sources, sandbox, builds and ELF

**Files:** `src/patchcheck/{source,sandbox,worker,build,elf}.py`, `environment/Dockerfile`, `tests/unit/test_source.py`, `tests/integration/test_sandbox.py`, `targets/`, `configs/`, `oracles/`, `corpus/`.

**Interfaces:** `snapshot_versions(config, out) -> dict`; `Sandbox(image, limits).execute(command, workdir, mounts, env, stdin) -> dict`; `build_all(config, out) -> list[dict]`; raw ELF artifacts linked in BuildRecord.

- [ ] Write tests for dirty snapshots/diff validation and real native status, binary I/O, signal, timeout, memory/CPU/output bounds and missing command. Run tests before implementation.
- [ ] Implement container worker and lifecycle with process-group cleanup, bounded build environment and inspect evidence; verify actual Linux x86_64 ELF.
- [ ] Add two independent harmless source fixtures with genuine Git base/candidate revisions and documented independent oracle data; build all four cells.
- [ ] Run unit/integration tests; commit task.

### Task 3: Full pipeline and reports

**Files:** `src/patchcheck/{pipeline,report,cli,__main__}.py`, `tests/integration/test_pipeline.py`.

**Interfaces:** `run_pipeline(config_path, out) -> report`; `compare(report) -> report`;
`write_report(report, root) -> None`; `main(argv=None) -> int`.

- [ ] Write failing tests for 3 input modes × 4 cells, expected invalid rejection, regression truth table, schema/evidence validation and exit 40/30.
- [ ] Implement real matrix execution with input hashing, scoped artifacts, specialist incompleteness and CLI operations.
- [ ] Validate every generated record and referenced file, independently inspect reports; run all tests and commit.

### Task 4: Replay and stability

**Files:** `src/patchcheck/replay.py`, `tests/unit/test_replay.py`, pipeline/CLI replay wiring.

**Interfaces:** `replay(report_path, test_id, count=3) -> dict`; `stability(records) -> dict`.

- [ ] Write failing tests for rejection of counts below 3, output/status/signature instability and full paired replay evidence.
- [ ] Implement at least 3 re-executions of all four cells per selected test with hashes and conservative instability propagation.
- [ ] Run suite and verify saved replay records; commit.

### Task 5: Minimizer, regression corpus and portable bundle

**Files:** `src/patchcheck/{minimize,bundle}.py`, `tests/unit/test_minimize.py`, `tests/integration/test_reproduction.py`.

**Interfaces:** `ddmin(data, predicate, max_attempts, deadline) -> dict`;
`minimize_case(report_path, test_id) -> dict`; `make_bundle(report_path, dest) -> Path`;
`reproduce(bundle_path, out) -> report`.

- [ ] Write failing tests for match/mismatch/unknown, alternate error rejection, budget exhaustion, original/minimized evidence and automatic next-run corpus discovery.
- [ ] Implement bounded delta debugging using actual fixture runs and exact signatures; replay minimized input on both revisions/builds; register self-contained regression tests.
- [ ] Bundle exact source snapshots, patches, inputs, executable build instructions, three replay results, image identity, tool sources and dependency locks; safely unpack and rebuild in a clean directory.
- [ ] Run portable reproduction integration tests and verify hashes; commit.

### Task 6: CI, server execution and handoff

**Files:** `.github/workflows/framework.yml`, `ci/smoke.py`, `ci/server-run.sh`, `README.md`, `HANDOFF.md`, `ACCEPTANCE.md`, `docs/{teacher-proposal,contributions,defense}.md`, `docs/evidence/`.

**Interfaces:** `python ci/smoke.py` returns framework test status while retaining each real CLI exit code in a manifest.

- [ ] Execute smoke pipeline from a clean checkout; collect raw Linux environment, tool versions, x86_64/ELF/build matrix, replay, minimization and bundle evidence.
- [ ] Use designated SSH server after read-only inventory; apply only dedicated bounded workloads, record before/after services and containers.
- [ ] Write accurate A13 acceptance mapping, exact phase-two extension locations, teacher approval pending and unclaimed human contributions.
- [ ] Run full suite, fresh whole-branch review, fix important findings with regression tests, verify final clean status and commit.
