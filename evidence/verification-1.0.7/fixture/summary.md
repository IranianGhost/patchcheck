# Patchcheck: bytecount

**Verdict: 40 INCONCLUSIVE** (fixture target)

Versions: base `1b303c4e13` → candidate `4fcf0ba260`
Builds: 4; tests: 5; executions: 55.

| Axis | Result |
|---|---|
| Security | unknown (target reproduced on base: no) |
| Functional | preserved |
| Analysis complete | no |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | not_run | finding-security-marker-release |
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | not_run | finding-security-marker-sanitized |
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | stable | finding-security-min-894f184a9720-release |
| Inconclusive | fixture-marker | explicit-fixture-protocol | marker-check | fixture | stable | finding-security-min-894f184a9720-sanitized |

## Patch correlation

Confirmed relationships cite a relevant stack frame or a covered changed line in the matching version. Unknown relationships lack sufficient evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-marker-release | Inconclusive | **unknown** | - | fixture evidence has no stack |
| finding-security-marker-sanitized | Inconclusive | **unknown** | - | fixture evidence has no stack |
| finding-security-min-894f184a9720-release | Inconclusive | **unknown** | - | fixture evidence has no stack |
| finding-security-min-894f184a9720-sanitized | Inconclusive | **unknown** | - | fixture evidence has no stack |

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
| finding-security-marker-release | out-of-scope | no | yes | min-894f184a9720 | insufficient evidence for minimization |
| finding-security-marker-sanitized | out-of-scope | no | yes | min-894f184a9720 | insufficient evidence for minimization |
| finding-security-min-894f184a9720-release | out-of-scope | no | no | - | insufficient evidence for minimization |
| finding-security-min-894f184a9720-sanitized | out-of-scope | no | no | - | insufficient evidence for minimization |

## Why the analysis is not complete

- baseline-not-reproduced: the target error was not observed on the base version
- inconclusive-finding: finding-security-marker-release
- inconclusive-finding: finding-security-marker-sanitized
- inconclusive-finding: finding-security-min-894f184a9720-release
- inconclusive-finding: finding-security-min-894f184a9720-sanitized
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
| min-894f184a9720 | release | fail | pass | baseline_fail |
| min-894f184a9720 | sanitized | fail | pass | baseline_fail |

## Crash classification

No abnormal termination was observed.
