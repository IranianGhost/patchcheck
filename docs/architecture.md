# Architecture

The framework began as a stage-one delivery at commit `91ae508` (original
specification: `docs/history/stage-one-requirements.fa.md`); stage two (crash
classification, verdicts, correlation, hardening, real targets) is now complete.
Python 3.11+, exact dependencies in
`requirements.lock`, dependency wheel checksums in `vendor/wheels/SHA256SUMS.json`.
Run the clean-install and test commands in README without this conversation.

## Architecture / C4 mapping

| C4 record | Real schema / producer |
|---|---|
| TargetConfig | `schemas/TargetConfig.schema.json`; `contracts.load_config` |
| TestCase | `schemas/TestCase.schema.json`; `pipeline.prepare_tests` |
| BuildRecord | `schemas/BuildRecord.schema.json`; `build.build_all` |
| RunRecord | `schemas/RunRecord.schema.json`; `pipeline.execute_test` |
| Finding | `schemas/Finding.schema.json`; `pipeline.compare_report` |
| PatchRelation | `schemas/PatchRelation.schema.json`; `analysis.correlate` (source map: `sourcemap.annotate`) |
| FinalReport | `schemas/FinalReport.schema.json`; `report.write_report` |
| Independent oracle | `schemas/Oracle.schema.json`; `oracle.evaluate_oracle` |

Schema version is 1.0, Draft 2020-12; required fields, enums and nullable values
are explicit. Canonical generated schemas are in `schemas/`; installable copies
are package data under `src/patchcheck/schemas/`. Regenerate both with
`python tools/generate_schemas.py`. Missing build outputs use explicit null hash/
binary fields and `result=failed`, never a fake executable hash.

`source.py` materializes independent Git trees, validates a supplied binary patch,
preserves dirty state, full binary-safe source archives and a self-contained Git
snapshot bundle. Original commit IDs and snapshot-repository IDs are distinct;
reproduction retains original provenance separately and verifies source manifests.
`build.py` constructs four cells and `elf.py` records actual ELF header/program/
dynamic/symbol evidence. `sandbox.py` owns bounded container lifecycles and
`worker.py` independently measures native status and rusage. Docker exit status
is stored in sandbox state; native `exit_code` and positive `signal` are separate.
An OOM-killed worker can have unknown target status and empty incomplete output;
the tool does not invent a target signal from Docker's 137 convention.

`oracle.py` evaluates each version against the same independent reference;
`decision.py` implements precedence 30 > 10 > 20 > 40 > 0, and
`pipeline.compare_report` feeds it from evidence (see "Verdict rules" below).
Fixture observations never count as confirmed real security findings.

### Verdict rules (`pipeline.compare_report`)

Per test and build type, the base and candidate runs are paired:

| Base | Candidate | Finding status |
|---|---|---|
| confirmed crash | clean | Fixed (Inconclusive if the candidate ended with an unclassified signal/timeout) |
| confirmed crash | same failure (`same_failure` = match) | Incomplete Fix |
| confirmed crash | different failure | New Issue |
| clean | confirmed crash | New Issue |
| any | only an unclassified signal/timeout | Inconclusive |

Unstable or unknown replays and fixture evidence force Inconclusive. Same failure
means equal signatures, or, in release builds without a location, the same error
type and detector. Tests in categories `original`/`minimized` target the
vulnerability; the rest are functional. Inputs to `decide`:

- confirmed security issue: a confirmed Incomplete Fix or New Issue;
- functional regression: a valid/boundary test passing on base fails on the candidate;
- baseline reproduced: a base run of a security test shows the declared target
  signature (any confirmed crash if the test declares none);
- incomplete: missing executions, no security tests, baseline not reproduced,
  functional tests failing on base or changed on invalid input, Inconclusive findings,
  unstable replays, or a fixture target. Each cause is listed in
  `axes.completeness.reasons` and in `summary.md`.

`replay.py` requires >=3 **additional** runs per cell. Equality includes native
status, resource/timeout/truncation, stdout/stderr hashes and signature, excluding
duration, rusage and UUID. The original run is also compared. Every run is saved.
`minimize.py` performs bounded ddmin accepting only `match`; original/minimized
bytes, every attempted input, hashes and match evidence are retained. The
direction is chosen from the report (`minimize.choose_direction`): a
**base-vulnerability** input minimizes against `base/sanitized` and must stay clean
on the candidate; a **candidate-only (New Issue)** input minimizes against
`candidate/sanitized` (with a clean base) and must keep the base clean. Final
validation and stable threefold replay precede corpus registration. The signature
is a sanitized-build crash, so a release build that does not surface the bug (e.g.
an out-of-bounds read no hardening check catches, as in giflib) is accepted rather
than failing validation; the same rule applies to the `generated_regression` check
when the test is later re-run. An original oracle is reused only if the minimized
candidate actually satisfies it; otherwise registration fails rather than deriving
an oracle from the candidate.

Generated `corpus/<target>/regressions/*.test.json` manifests include the signature,
input hash, independent oracle and requirements. Two kinds exist: base-vulnerability
(`base_match_required` + `candidate_absence_and_oracle_required`) and candidate-only
(`base_absence_required` + `candidate_reproduce_required`, for a New Issue).
`pipeline.prepare_tests` discovers these on the next invocation, and the
`generated_regression` per-build result (with a `direction` discriminator) appears
in the functional comparisons. Other JSON files in the corpus are not test manifests.

## CLI operations

All C4 proposed names are retained: `validate-config`, `build`, `run`, `compare`,
`replay`, `minimize`, `report`. Added `bundle` and `reproduce`. `--help` documents
arguments. `run` includes validation, both builds, full matrix and comparison.
`run`/`build` take `--base`/`--candidate` to override the configured Git refs, or
`--patch FILE` to evaluate an unseen unified diff applied to base (the defense-day
flow; `source.apply_patch_tree` applies it in a throwaway repo, so paths cannot
escape the tree). `--patch` is mutually exclusive with `--candidate` and with
`source.diff`/`source.dirty`.
`build` stops after building and returns 0 for successful build infrastructure,
while its report remains incomplete 40. `compare` recomputes from saved real
records; it has no verdict override. Replay/minimize/report return the real report
code. Bundle creation returns 0 for a successful archive operation. All technical
failures return 30. Output directories must be empty; existing evidence is not
silently overwritten. Re-run with a fresh directory.

## Phase-two extension contracts and exact remaining work

1. **Done:** `analysis.analyze(run_record, stderr) -> {complete, observations, reason}`.
   Each observation keeps error type, detection method (asan, ubsan, fortify-source,
   stack-protector, glibc-malloc-check, os-signal, time-limit, resource-limit),
   termination (exit code / signal / timeout / limit), access kind and size, the
   first in-program stack frame, related allocation/free stacks, and a signature
   `{error_type, location: "file:function", key: access kind or error type}`.
   Line numbers are kept in `location` but excluded from the signature because
   patches shift them. Bare signals are `unclassified` with no signature; root cause
   is never inferred. Tests use real diagnostics recorded by
   `tests/unit/data/crashes/record.sh`. Replay compares classified crashes instead
   of raw stderr bytes (sanitizer addresses vary with ASLR).
2. **Done:** `analysis.match_failure(expected_signature, observed) -> match|mismatch|unknown`
   compares `{error_type, location, key}` with complete evidence only.
   `security_observation(run)` returns the detector-backed failure of a run (or the
   fixture marker for fixtures); the minimizer, generated regression checks and
   verdict all use it. The fixture-only minimization guard is removed.
3. **Done:** `analysis.correlate(diff, findings, paired_runs) -> list[PatchRelation]`.
   At snapshot time `source.parse_hunks` records the exact changed lines of each
   hunk (blank/comment lines ignored, `#define` names kept) and `sourcemap.annotate`
   maps them to the enclosing C/C++ function in base and candidate, and stores static
   callers of every changed function and users of every changed macro. `correlate`
   then compares the hunks with the stack of the failing run (crash site, callers,
   allocation/free stacks; base for Fixed/Incomplete Fix, candidate for New Issue):
   - `confirmed`: a changed function, or a function using a changed macro, is on
     that stack, and the paired runs on the same input agree with the finding;
   - `rejected`: an Incomplete Fix whose failure persists, whose stack reaches `main`,
     with every hunk mapped to a function and none on the stack (changed functions
     that are only called from the stack are listed as `callee-of-path` evidence);
   - `unknown`: everything else: release builds (no stack; the sanitized pair is
     referenced), functional regressions, unmapped hunks, or a fix off the stack.
   Each location records hunk, file, function, role, frame index and whether the
   frame line itself changed; proximity alone never decides. The scanner is
   lexical (`sourcemap.py`), not a compiler front end.
   Functional regressions have no crash stack, so their relation instead uses
   coverage for the same input on separate gcov diagnostic builds. Added lines
   are checked on the candidate after verifying the same failed oracle checks
   and observed exit code or output hashes. Removed lines are checked on the
   baseline after verifying the same passing oracle checks. Each location carries
   its version, covered lines and diagnostic run ID. Missing or mismatched
   evidence leaves that side unconfirmed. Diagnostic stdout and stderr are saved
   as hashed evidence. Coverage identifies lines on the observed execution path.
4. **Done:** hardening comparison. `elf.raw_hardening` extracts indicators from
   `readelf -W -h -l -d -s` (raw output and readelf version kept per build);
   `elf.interpret` turns them into NX (PT_GNU_STACK RW/RWE), PIE (DYN + FLAGS_1 PIE /
   EXEC), RELRO (none/partial/full via GNU_RELRO + BIND_NOW), stack canary
   (`__stack_chk_fail`) and FORTIFY (`__*_chk`) values; `elf.compare_hardening`
   compares both Release binaries. Weaker NX/PIE/RELRO on the candidate is
   `degraded`: it adds a `hardening-degraded` completeness reason and feeds
   `hardening_degraded` to `decide`, so such a patch cannot PASS (40). Lost canary/
   FORTIFY symbols are only warnings, because the compiler emits them only when a
   function needs them, so their absence is no proof. Differing release flags/commands are
   reported. Tests use real readelf output of tlvparse built with each protection
   removed (`tests/unit/data/elf/record.sh`).
   `elf.instrumentation_markers` (and `build.validate_instrumentation`) checks the
   sanitizer runtime symbols of *both* builds: a sanitized build must carry its
   declared markers (else 30), and a release build that carries a sanitizer runtime
   is rejected with 30 too. `analysis.analyze` only classifies ASan/UBSan text on a
   `sanitized` build; the same text on a release build falls through to the libc and
   bare-signal paths and is recorded unclassified.
5. **Done:** real findings, completeness reasons and the decision engine are wired
   into `pipeline.compare_report`; the forced 40 is removed (report `stage` is 2).
   Hardening degradation is an input to `decide` (see item 4).
6. **Done:** real targets. Two programs with four scenario versions each
   are wired with no target-specific verdict code, through the JSON build/input
   knobs only: `tlvparse` (our own program) and `giflib` `gif2rgb` (the real
   project, CVE-2016-3977 — `base` = upstream `c9a54af`, `correct` = upstream fix
   `ea8dbc57`, plus our `incomplete`/`regression` edits). Independent oracles carry
   provenance (source document and an `independent` flag). giflib inputs are
   GIF89a files built from the spec by `tools/gen_giflib_corpus.py`. Still open:
   the unseen patches handed out on defense day (which run through `--candidate`
   with no code change).

These are explicit phase-two deliverables, not claims of final-project completion.
Human group membership and contributions remain unclaimed.

## Limitations and reproducibility boundaries

- Linux x86_64 is required for target execution; local Mac evidence is emulated.
- A bug that is an out-of-bounds *read* (e.g. giflib CVE-2016-3977) does not crash
  the hardened release build; it prints the bytes it read, so that build's output is
  nondeterministic. The replay-stability check (`replay.py`) does not require a base
  build that never shows a confirmed crash to be stable, so such a bug is still
  classified, verdicted, replayed and minimized on the sanitized build where the
  crash lives. Its 44-byte PoC cannot be reduced by ddmin (every GIF header field is
  needed to reach the read), so the registered regression has the PoC's bytes. CI
  minimizes and re-runs a generated regression on both tlvparse and giflib.
- Source symlinks/special files and argv NUL/non-UTF8/>32768-byte inputs are rejected.
- No target networking; builds must use already-installed dependencies.
- A trusted Docker worker is required; Docker is an isolation boundary, not a VM.
- Bundle includes image.tar by default for exact offline toolchain restoration.
  An optional lighter bundle requires the exact image locally and includes the frozen
  recipe; an arbitrary rebuilt image is not silently accepted as identical.
- JSON/regex/exact oracles have no normalization. Regexes/configured build commands
  are trusted project configuration, not a hosted service accepting hostile configs.
- The repository is hosted at github.com/M-H-Boroumandnia/patchcheck (private) and
  CI runs on every push via `.github/workflows/framework.yml`.
