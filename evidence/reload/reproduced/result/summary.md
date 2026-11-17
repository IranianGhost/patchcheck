# Patchcheck: bytecount

**Verdict: 40 INCONCLUSIVE** (fixture target)

Versions: base `bd80e421dd` → candidate `6b98a8e8f1`
Builds: 4; tests: 5; executions: 44.

| Axis | Result |
|---|---|
| Security | unknown (target reproduced on base: no) |
| Functional | preserved |
| Analysis complete | no |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | stable | finding-security-marker-release |
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | stable | finding-security-marker-sanitized |
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | stable | finding-security-min-c76b5c10ac93-release |
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | stable | finding-security-min-c76b5c10ac93-sanitized |

## Patch correlation

confirmed = a changed function is on the failing stack; rejected = the failure persists and the patch does not touch its stack; unknown = not enough evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-marker-release | Inconclusive | **unknown** | - | fixture evidence has no stack |
| finding-security-marker-sanitized | Inconclusive | **unknown** | - | fixture evidence has no stack |
| finding-security-min-c76b5c10ac93-release | Inconclusive | **unknown** | - | fixture evidence has no stack |
| finding-security-min-c76b5c10ac93-sanitized | Inconclusive | **unknown** | - | fixture evidence has no stack |

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |
| fortify_source | not-observed | not-observed | same |

## Why the analysis is not complete

- baseline-not-reproduced: the target error was not observed on the base version
- inconclusive-finding: finding-security-marker-release
- inconclusive-finding: finding-security-marker-sanitized
- inconclusive-finding: finding-security-min-c76b5c10ac93-release
- inconclusive-finding: finding-security-min-c76b5c10ac93-sanitized
- fixture-target: fixture evidence never validates a real patch

## Technical errors

- none

## Known limitations

- Patch correlation uses static stacks and a lexical source map; code that returned before a crash is not on its stack, and release builds have no stack.
- Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof that the protection is off.

## Functional comparisons

| Test | Build | Base oracle | Candidate oracle | Comparison |
|---|---|---|---|---|
| binary | release | pass | pass | preserved |
| binary | sanitized | pass | pass | preserved |
| empty | release | pass | pass | preserved |
| empty | sanitized | pass | pass | preserved |
| invalid | release | pass | pass | preserved |
| invalid | sanitized | pass | pass | preserved |
| marker | release | fail | pass | baseline_fail |
| marker | sanitized | fail | pass | baseline_fail |
| min-c76b5c10ac93 | release | fail | pass | baseline_fail |
| min-c76b5c10ac93 | sanitized | fail | pass | baseline_fail |

## Crash classification

No abnormal termination was observed.
