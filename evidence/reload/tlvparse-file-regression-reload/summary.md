# Patchcheck: tlvparse

**Verdict: 0 PASS**

Versions: base `e9f37539fb` → candidate `e4635443a7`
Builds: 4; tests: 14; executions: 92.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | preserved |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Fixed | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-poc-long-name-release |
| Fixed | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-poc-long-name-sanitized |
| Fixed | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-poc-long-blob-release |
| Fixed | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-poc-long-blob-sanitized |
| Fixed | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-generated-afe24c6fd035b0ec-release |
| Fixed | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-generated-afe24c6fd035b0ec-sanitized |

## Patch correlation

confirmed = a changed function is on the failing stack; rejected = the failure persists and the patch does not touch its stack; unknown = not enough evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-poc-long-name-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair); sanitized pair finding-security-poc-long-name-sanitized is confirmed; this release relation stays unknown because it has no stack of its own |
| finding-security-poc-long-name-sanitized | Fixed | **confirmed** | h1 | h1 changes tlvparse.c:copy_value, the crash-site (frame #1) of the base failure; h1 changes tlvparse.c:copy_value, the allocation-stack (frame #1) of the base failure; the same input crashes base at tlvparse.c:copy_value and not the candidate |
| finding-security-poc-long-blob-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair); sanitized pair finding-security-poc-long-blob-sanitized is confirmed; this release relation stays unknown because it has no stack of its own |
| finding-security-poc-long-blob-sanitized | Fixed | **confirmed** | h1 | h1 changes tlvparse.c:copy_value, the crash-site (frame #1) of the base failure; h1 changes tlvparse.c:copy_value, the allocation-stack (frame #1) of the base failure; the same input crashes base at tlvparse.c:copy_value and not the candidate |
| finding-security-generated-afe24c6fd035b0ec-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair); sanitized pair finding-security-generated-afe24c6fd035b0ec-sanitized is confirmed; this release relation stays unknown because it has no stack of its own |
| finding-security-generated-afe24c6fd035b0ec-sanitized | Fixed | **confirmed** | h1 | h1 changes tlvparse.c:copy_value, the crash-site (frame #1) of the base failure; h1 changes tlvparse.c:copy_value, the allocation-stack (frame #1) of the base failure; the same input crashes base at tlvparse.c:copy_value and not the candidate |

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
| boundary-name32 | release | pass | pass | preserved |
| boundary-name32 | sanitized | pass | pass | preserved |
| boundary-blob32 | release | pass | pass | preserved |
| boundary-blob32 | sanitized | pass | pass | preserved |
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
| generated-afe24c6fd035b0ec | release | fail | pass | baseline_fail |
| generated-afe24c6fd035b0ec | sanitized | fail | pass | baseline_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-long-name | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-name | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 200 | tlvparse.c:31 in copy_value | confirmed |
| poc-long-blob | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-blob | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 100 | tlvparse.c:31 in copy_value | confirmed |
| generated-afe24c6fd035b0ec | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| generated-afe24c6fd035b0ec | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 66 | tlvparse.c:31 in copy_value | confirmed |
