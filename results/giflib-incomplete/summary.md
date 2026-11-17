# Patchcheck: giflib

**Verdict: 10 VULN_REMAINS / NEW_ISSUE**

Versions: base `d25b2aa287` → candidate `7f4edc7f5c`
Builds: 4; tests: 7; executions: 52.

| Axis | Result |
|---|---|
| Security | issue (target reproduced on base: yes) |
| Functional | unknown |
| Analysis complete | no |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Fixed | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-poc-bg-oob-sanitized |
| Incomplete Fix | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-poc-bg-far-sanitized |

## Patch correlation

confirmed = a changed function is on the failing stack; rejected = the failure persists and the patch does not touch its stack; unknown = not enough evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-security-poc-bg-oob-sanitized | Fixed | **confirmed** | h4 | h4 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h4 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; hunks outside any function (not mapped): h2; the same input crashes base at util/gif2rgb.c:DumpScreen2RGB and not the candidate |
| finding-security-poc-bg-far-sanitized | Incomplete Fix | **confirmed** | h4 | h4 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h4 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; h4 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the candidate failure; h4 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the candidate failure; hunks outside any function (not mapped): h2; the patch changes the failing path but the same failure at util/gif2rgb.c:DumpScreen2RGB persists on the candidate |

## Binary hardening (release builds)

| Protection | Base | Candidate | Change |
|---|---|---|---|
| fortify_source | present | present | same |
| nx | enabled | enabled | same |
| pie | enabled | enabled | same |
| relro | full | full | same |
| stack_canary | present | present | same |

## Why the analysis is not complete

- security-input-oracle: poc-bg-far (release) candidate=fail
- security-input-oracle: poc-bg-far (sanitized) candidate=fail

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
| invalid-oversize | release | pass | pass | preserved |
| invalid-oversize | sanitized | pass | pass | preserved |
| invalid-zero-dim | release | pass | pass | preserved |
| invalid-zero-dim | sanitized | pass | pass | preserved |
| poc-bg-oob | release | fail | pass | baseline_fail |
| poc-bg-oob | sanitized | fail | pass | baseline_fail |
| poc-bg-far | release | fail | fail | both_fail |
| poc-bg-far | sanitized | fail | fail | both_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-bg-oob | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
| poc-bg-far | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
| poc-bg-far | candidate | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
