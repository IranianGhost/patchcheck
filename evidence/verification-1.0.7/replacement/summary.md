# Patchcheck: bytecount

**Verdict: 20 FUNC_REGRESSION** (fixture target)

Versions: base `1b303c4e13` → candidate `1b303c4e13`
Builds: 4; tests: 1; executions: 4.

| Axis | Result |
|---|---|
| Security | unknown (target reproduced on base: no) |
| Functional | regression |
| Analysis complete | no |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Functional Regression | functional-regression | independent-oracle | - | confirmed | not_run | finding-functional-binary-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | not_run | finding-functional-binary-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-functional-binary-release | Functional Regression | **confirmed** | h1 | h1 changes main in main.c; covered lines [30] are executed by the passing baseline (test binary, diagnostic run coverage-binary-base-542e965673c6); h1 changes main in main.c; covered lines [30] are executed by the failing functional run (test binary, diagnostic run coverage-binary-candidate-3044977433e7) |
| finding-functional-binary-sanitized | Functional Regression | **confirmed** | h1 | h1 changes main in main.c; covered lines [30] are executed by the passing baseline (test binary, diagnostic run coverage-binary-base-542e965673c6); h1 changes main in main.c; covered lines [30] are executed by the failing functional run (test binary, diagnostic run coverage-binary-candidate-3044977433e7) |

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |
| fortify_source | not-observed | not-observed | same |

## Minimization coverage

Status: out-of-scope = not minimizable; supported = minimizable but not run; reduced / no-reduction / unstable / failed = outcome of an attempted run; registered = reduced-or-unchanged input written to the regression corpus; unrecorded = an older report did not record an outcome in this table.

| Finding | Status | Covered | Registered | Minimized test | Reason |
|---|---|---|---|---|---|
| finding-functional-binary-release | out-of-scope | no | no | - | functional regression has no crash signature to minimize |
| finding-functional-binary-sanitized | out-of-scope | no | no | - | functional regression has no crash signature to minimize |

## Why the analysis is not complete

- no-security-tests: no original/minimized input targets the vulnerability
- missing-test-category: no boundary input is configured
- missing-test-category: no invalid input is configured
- fixture-target: fixture evidence never validates a real patch

## Technical errors

- none

## Known limitations

- Patch correlation uses static stacks and a lexical source map; code that returned before a crash is not on its stack, and release builds have no stack.
- Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof that the protection is off.

## Functional comparisons

| Test | Build | Base oracle | Candidate oracle | Comparison |
|---|---|---|---|---|
| binary | release | pass | fail | regression |
| binary | sanitized | pass | fail | regression |

## Crash classification

No abnormal termination was observed.
