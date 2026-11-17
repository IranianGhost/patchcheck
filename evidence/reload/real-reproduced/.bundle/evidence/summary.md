# Patchcheck: tlvparse

**Verdict: 10 VULN_REMAINS / NEW_ISSUE**

Versions: base `e9f37539fb` → candidate `2e845e88c9`
Builds: 4; tests: 13; executions: 76.

| Axis | Result |
|---|---|
| Security | issue (target reproduced on base: yes) |
| Functional | unknown |
| Analysis complete | no |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Fixed | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-poc-long-name-release |
| Fixed | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-poc-long-name-sanitized |
| Incomplete Fix | buffer-overflow | fortify-source | - | confirmed | stable | finding-security-poc-long-blob-release |
| Incomplete Fix | heap-buffer-overflow | asan | tlvparse.c:31 in copy_value | confirmed | stable | finding-security-poc-long-blob-sanitized |

## Patch correlation

confirmed = a changed function is on the failing stack; rejected = the failure persists and the patch does not touch its stack; unknown = not enough evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-poc-long-name-release | Fixed | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair); sanitized pair finding-security-poc-long-name-sanitized is confirmed; this release relation stays unknown because it has no stack of its own |
| finding-security-poc-long-name-sanitized | Fixed | **confirmed** | h1 | h1 changes tlvparse.c:load_name, the caller (frame #2) of the base failure; h1 changes tlvparse.c:load_name, the allocation-stack (frame #2) of the base failure; the same input crashes base at tlvparse.c:copy_value and not the candidate |
| finding-security-poc-long-blob-release | Incomplete Fix | **unknown** | - | the base release run has no symbolized in-program stack (see the sanitized pair) |
| finding-security-poc-long-blob-sanitized | Incomplete Fix | **unknown** | h1 | h1 changes tlvparse.c:load_name, called from parse on the stack but not itself on the failing stack; the failure at tlvparse.c:copy_value persists on the candidate and no hunk changes a function on its stack (complete down to main); a changed function may still have run and returned earlier, so the relation cannot be rejected from the stack alone |

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |
| fortify_source | present | present | same |

## Why the analysis is not complete

- security-input-oracle: poc-long-blob (release) candidate=fail
- security-input-oracle: poc-long-blob (sanitized) candidate=fail

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
| poc-long-blob | release | fail | fail | both_fail |
| poc-long-blob | sanitized | fail | fail | both_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-long-name | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-name | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 200 | tlvparse.c:31 in copy_value | confirmed |
| poc-long-blob | base | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-blob | base | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 100 | tlvparse.c:31 in copy_value | confirmed |
| poc-long-blob | candidate | release | buffer-overflow | fortify-source | SIGABRT | - | - | confirmed |
| poc-long-blob | candidate | sanitized | heap-buffer-overflow | asan | SIGABRT | WRITE 100 | tlvparse.c:31 in copy_value | confirmed |
