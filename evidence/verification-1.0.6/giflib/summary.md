# Patchcheck: giflib

**Verdict: 40 INCONCLUSIVE**

Versions: base `d25b2aa287` → candidate `da3cacdc98`
Builds: 4; tests: 3; executions: 12.

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
- missing-test-category: no invalid input is configured

## Technical errors

- none

## Known limitations

- Patch correlation uses static stacks and a lexical source map; code that returned before a crash is not on its stack, and release builds have no stack.
- Hardening uses readelf indicators; missing canary/FORTIFY symbols are not proof that the protection is off.

## Functional comparisons

| Test | Build | Base oracle | Candidate oracle | Comparison |
|---|---|---|---|---|
| valid-fill | release | pass | pass | preserved |
| valid-fill | sanitized | pass | pass | preserved |
| valid-margin | release | pass | pass | preserved |
| valid-margin | sanitized | pass | pass | preserved |
| boundary-bg-max | release | pass | pass | preserved |
| boundary-bg-max | sanitized | pass | pass | preserved |

## Crash classification

No abnormal termination was observed.
