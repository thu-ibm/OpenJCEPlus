# openssl_aes: All 10 AES Tests Pass
**Date:** 2026-07-24

## What Was Done

### 1. Confirmed openssl_aes is the thu-ibm:main working directory
- Remote: `git@github.com:thu-ibm/OpenJCEPlus.git`
- Latest upstream commit: `9d53388 Add OpenJCEPlusFIPS to module-info.java provider registration (#1651)`
- All ojp_master integration files already applied (same pattern as completed PR1492 integration)
- Pre-built `libjgskit_openssl_64.dll` SHA256 matches the copy in `%JAVA_HOME%\bin\` — no rebuild needed

### 2. Fixed pom.xml malformed XML
- **Root cause:** A stray duplicate `<systemProperty>` open tag at line 363 (with no closing `</systemProperty>`)
  followed by a duplicate `openssl.library.path` entry — left over from a bad merge/paste when applying
  the PR1492 pom.xml additions onto thu-ibm:main.
- **Error:** `end tag name </systemProperties> must match start tag name <systemProperty> from line 363`
- **Fix:** Removed the 5-line orphaned block (bare `<systemProperty>` + duplicate `openssl.library.path` entry)
- **Preserved:** The `thu-ibm:main`-specific `<build.target.ojplib.dir>ojp-mz-64/</build.target.ojplib.dir>`
  entry at line 68 (not present in PR1492 — new platform profile)
- Decision rationale: did NOT take PR1492's pom.xml wholesale — it would have lost the mz-64 profile

### 3. Ran run_all_aes_tests.bat from openssl_aes\
All 10/10 test classes passed:

| # | Test Class | Tests | Result |
|---|-----------|-------|--------|
| 1 | TestAES256Interop | 18 | ✅ PASS |
| 2 | TestAESKeyWrap | 64 | ✅ PASS |
| 3 | TestAESGCMUpdate | 20 | ✅ PASS |
| 4 | TestAESGCMWithKeyAndIvCheck | 1 | ✅ PASS |
| 5 | TestAESGCMUpdateInteropBC | 3 | ✅ PASS |
| 6 | TestAESGCMBufferIV | 1 | ✅ PASS |
| 7 | TestAESGCM_ExtIV | 28 | ✅ PASS |
| 8 | TestAESGCM_IntIV | 8 | ✅ PASS |
| 9 | TestAESCCMParameters | 3 | ✅ PASS |
| 10 | TestAESCCMInteropBC | 2 | ✅ PASS |

**Total: 148 test methods, 0 failures**

## Current State

- Workspace: `c:\Users\Administrator\openjdk_dev\openssl_aes\`
- Branch: `main`, remote `thu-ibm/OpenJCEPlus`
- All changes are uncommitted (working tree modifications + untracked new files)
- DLL: pre-built `libjgskit_openssl_64.dll` (B16C8831...) deployed in `%JAVA_HOME%\bin\`

## What Remains

1. Review and apply unapplied commits from https://github.com/IBM/OpenJCEPlus/pull/1492/commits
   that have not yet been incorporated into openssl_aes
2. Commit the working state in openssl_aes
3. Push / create PR against thu-ibm/OpenJCEPlus or IBM/OpenJCEPlus as appropriate
