# Patchcheck: tlvparse

**Verdict: 40 INCONCLUSIVE**

Versions: base `e9f37539fb` → candidate `e4635443a7`
Builds: 4; tests: 4; executions: 16.

| Axis | Result |
|---|---|
| Security | unknown (target reproduced on base: no) |
| Functional | preserved |
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
| fortify_source | present | present | same |

## Minimization coverage

No findings to report minimization scope for.

## Why the analysis is not complete

- no-security-tests: no original/minimized input targets the vulnerability

## Technical errors

- none

## Known limitations

- Patch correlation uses static stacks and a lexical source map; code that returned before a crash is not on its stack, and release builds have no stack.
- Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof that the protection is off.

## Functional comparisons

| Test | Build | Base oracle | Candidate oracle | Comparison |
|---|---|---|---|---|
| valid-basic | release | pass | pass | preserved |
| valid-basic | sanitized | pass | pass | preserved |
| valid-empty | release | pass | pass | preserved |
| valid-empty | sanitized | pass | pass | preserved |
| boundary-blob32 | release | pass | pass | preserved |
| boundary-blob32 | sanitized | pass | pass | preserved |
| invalid-magic | release | pass | pass | preserved |
| invalid-magic | sanitized | pass | pass | preserved |

## Crash classification

No abnormal termination was observed.
