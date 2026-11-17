# Patchcheck: tlvparse

**Verdict: 20 FUNC_REGRESSION**

Versions: base `e9f37539fb` → candidate `d56c396f35`
Builds: 4; tests: 13; executions: 100.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | regression |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-name32-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-name32-sanitized |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-blob32-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-blob32-sanitized |
| Fixed | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-poc-long-name-release |
| Fixed | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-poc-long-name-sanitized |
| Fixed | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-poc-long-blob-release |
| Fixed | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-poc-long-blob-sanitized |

## Patch correlation

confirmed = a changed function is on the failing stack; rejected = the failure persists and the patch does not touch its stack; unknown = not enough evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-functional-boundary-name32-release | Functional Regression | **confirmed** | - | h1 changes copy_value in tlvparse.c; covered lines [28, 29] are executed by the failing functional run (test boundary-name32, diagnostic run coverage-boundary-name32-7fa9595b730b) |
| finding-functional-boundary-name32-sanitized | Functional Regression | **confirmed** | - | h1 changes copy_value in tlvparse.c; covered lines [28, 29] are executed by the failing functional run (test boundary-name32, diagnostic run coverage-boundary-name32-7fa9595b730b) |
| finding-functional-boundary-blob32-release | Functional Regression | **confirmed** | - | h1 changes copy_value in tlvparse.c; covered lines [28, 29] are executed by the failing functional run (test boundary-blob32, diagnostic run coverage-boundary-blob32-70cd1e471630) |
| finding-functional-boundary-blob32-sanitized | Functional Regression | **confirmed** | - | h1 changes copy_value in tlvparse.c; covered lines [28, 29] are executed by the failing functional run (test boundary-blob32, diagnostic run coverage-boundary-blob32-70cd1e471630) |
| finding-security-poc-long-name-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair); sanitized pair finding-security-poc-long-name-sanitized is confirmed; this release relation stays unknown because it has no stack of its own |
| finding-security-poc-long-name-sanitized | Fixed | **confirmed** | h1 | h1 changes tlvparse.c:copy_value, the crash-site (frame #1) of the base failure; h1 changes tlvparse.c:copy_value, the allocation-stack (frame #1) of the base failure; the same input crashes base at tlvparse.c:copy_value and not the candidate |
| finding-security-poc-long-blob-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair); sanitized pair finding-security-poc-long-blob-sanitized is confirmed; this release relation stays unknown because it has no stack of its own |
| finding-security-poc-long-blob-sanitized | Fixed | **confirmed** | h1 | h1 changes tlvparse.c:copy_value, the crash-site (frame #1) of the base failure; h1 changes tlvparse.c:copy_value, the allocation-stack (frame #1) of the base failure; the same input crashes base at tlvparse.c:copy_value and not the candidate |

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| fortify_source | present | present | same |
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |

## Why the analysis is not complete

- (complete)

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
| valid-negative | release | pass | pass | preserved |
| valid-negative | sanitized | pass | pass | preserved |
| boundary-name32 | release | pass | fail | regression |
| boundary-name32 | sanitized | pass | fail | regression |
| boundary-blob32 | release | pass | fail | regression |
| boundary-blob32 | sanitized | pass | fail | regression |
| boundary-16records | release | pass | pass | preserved |
| boundary-16records | sanitized | pass | pass | preserved |
| invalid-magic | release | pass | pass | preserved |
| invalid-magic | sanitized | pass | pass | preserved |
| invalid-truncated | release | pass | pass | preserved |
| invalid-truncated | sanitized | pass | pass | preserved |
| invalid-type | release | pass | pass | preserved |
| invalid-type | sanitized | pass | pass | preserved |
| invalid-numlen | release | pass | pass | preserved |
| invalid-numlen | sanitized | pass | pass | preserved |
| invalid-17records | release | pass | pass | preserved |
| invalid-17records | sanitized | pass | pass | preserved |
| poc-long-name | release | fail | pass | baseline_fail |
| poc-long-name | sanitized | fail | pass | baseline_fail |
| poc-long-blob | release | fail | pass | baseline_fail |
| poc-long-blob | sanitized | fail | pass | baseline_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-long-name | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-name | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 200 | tlvparse.c:31 in copy_value | confirmed |
| poc-long-blob | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-blob | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 100 | tlvparse.c:31 in copy_value | confirmed |
