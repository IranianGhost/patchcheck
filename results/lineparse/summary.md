# Patchcheck: lineparse

**Verdict: 40 INCONCLUSIVE** (fixture target)

Versions: base `0fcf9cebb0` → candidate `33ae3023c7`
Builds: 4; tests: 4; executions: 16.

| Axis | Result |
|---|---|
| Security | unknown (target reproduced on base: no) |
| Functional | unknown |
| Analysis complete | no |

## Findings

No findings.

## Patch correlation

No findings to correlate.

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |
| fortify_source | not-observed | not-observed | same |

## Why the analysis is not complete

- no-security-tests: no original/minimized input targets the vulnerability
- functional-unknown: plus (release) base=fail candidate=pass
- functional-unknown: plus (sanitized) base=fail candidate=pass
- fixture-target: fixture evidence never validates a real patch

## Technical errors

- none

## Known limitations

- Patch correlation uses static stacks and a lexical source map; code that returned before a crash is not on its stack, and release builds have no stack.
- Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof that the protection is off.

## Functional comparisons

| Test | Build | Base oracle | Candidate oracle | Comparison |
|---|---|---|---|---|
| seven | release | pass | pass | preserved |
| seven | sanitized | pass | pass | preserved |
| plus | release | fail | pass | baseline_fail |
| plus | sanitized | fail | pass | baseline_fail |
| low | release | pass | pass | preserved |
| low | sanitized | pass | pass | preserved |
| invalid | release | pass | pass | preserved |
| invalid | sanitized | pass | pass | preserved |

## Crash classification

No abnormal termination was observed.
