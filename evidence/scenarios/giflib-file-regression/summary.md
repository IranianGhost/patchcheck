# Patchcheck: giflib

**Verdict: 20 FUNC_REGRESSION**

Versions: base `d25b2aa287` → candidate `60c47eab4a`
Builds: 4; tests: 7; executions: 76.

| Axis | Result |
|---|---|
| Security | fixed (target reproduced on base: yes) |
| Functional | regression |
| Analysis complete | yes |

## Findings

| Status | Error type | Detection | Location | Evidence | Replay | Id |
|---|---|---|---|---|---|---|
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-valid-margin-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-valid-margin-sanitized |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-bg-max-release |
| Functional Regression | functional-regression | independent-oracle | - | confirmed | stable | finding-functional-boundary-bg-max-sanitized |
| Fixed | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-poc-bg-oob-sanitized |
| Fixed | heap-buffer-overflow | asan | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed | stable | finding-security-poc-bg-far-sanitized |

## Patch correlation

confirmed = a changed function is on the failing stack; rejected = the failure persists and the patch does not touch its stack; unknown = not enough evidence.

| Finding | Status | Relation | Hunks | Evidence |
|---|---|---|---|---|
| finding-functional-valid-margin-release | Functional Regression | **confirmed** | - | h4 changes GIF2RGB in util/gif2rgb.c; covered lines [475, 476, 477] are executed by the failing functional run (test valid-margin, diagnostic run coverage-valid-margin-a279660237b2) |
| finding-functional-valid-margin-sanitized | Functional Regression | **confirmed** | - | h4 changes GIF2RGB in util/gif2rgb.c; covered lines [475, 476, 477] are executed by the failing functional run (test valid-margin, diagnostic run coverage-valid-margin-a279660237b2) |
| finding-functional-boundary-bg-max-release | Functional Regression | **confirmed** | - | h4 changes GIF2RGB in util/gif2rgb.c; covered lines [475, 476, 477] are executed by the failing functional run (test boundary-bg-max, diagnostic run coverage-boundary-bg-max-0073709c6b4a) |
| finding-functional-boundary-bg-max-sanitized | Functional Regression | **confirmed** | - | h4 changes GIF2RGB in util/gif2rgb.c; covered lines [475, 476, 477] are executed by the failing functional run (test boundary-bg-max, diagnostic run coverage-boundary-bg-max-0073709c6b4a) |
| finding-security-poc-bg-oob-sanitized | Fixed | **confirmed** | h4 | h4 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h4 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; hunks outside any function (not mapped): h2; the same input crashes base at util/gif2rgb.c:DumpScreen2RGB and not the candidate |
| finding-security-poc-bg-far-sanitized | Fixed | **confirmed** | h4 | h4 changes util/gif2rgb.c:GIF2RGB, the caller (frame #1) of the base failure; h4 changes util/gif2rgb.c:GIF2RGB, the allocation-stack (frame #1) of the base failure; hunks outside any function (not mapped): h2; the same input crashes base at util/gif2rgb.c:DumpScreen2RGB and not the candidate |

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
| valid-fill | release | pass | pass | preserved |
| valid-fill | sanitized | pass | pass | preserved |
| valid-margin | release | pass | fail | regression |
| valid-margin | sanitized | pass | fail | regression |
| boundary-bg-max | release | pass | fail | regression |
| boundary-bg-max | sanitized | pass | fail | regression |
| invalid-oversize | release | pass | pass | preserved |
| invalid-oversize | sanitized | pass | pass | preserved |
| invalid-zero-dim | release | pass | pass | preserved |
| invalid-zero-dim | sanitized | pass | pass | preserved |
| poc-bg-oob | release | fail | pass | baseline_fail |
| poc-bg-oob | sanitized | fail | pass | baseline_fail |
| poc-bg-far | release | fail | pass | baseline_fail |
| poc-bg-far | sanitized | fail | pass | baseline_fail |

## Crash classification

| Test | Version | Build | Error type | Detection | Termination | Access | Location | Evidence |
|---|---|---|---|---|---|---|---|---|
| poc-bg-oob | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
| poc-bg-far | base | sanitized | heap-buffer-overflow | asan | SIGABRT | READ 1 | util/gif2rgb.c:294 in DumpScreen2RGB | confirmed |
