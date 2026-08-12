# Session Handoff 2 — Context for Next Task
**Date:** 2026-07-27

---

## Workspace

| Item | Value |
|------|-------|
| Path | `c:\Users\Administrator\openjdk_dev\thu_main` |
| Branch | `openssl-aes` |
| Remote origin | `git@github.com:thu-ibm/OpenJCEPlus.git` |
| Remote kostas | `git@github.com:KostasTsiounis/OpenJCEPlus.git` (PR#1492) |
| Base commit | `9d53388` (thu-ibm/main HEAD) |

---

## Environment

| Variable | Value |
|----------|-------|
| JAVA_HOME | `C:\Users\Administrator\Downloads\opensdk\semeru\jdk` |
| OPENSSL_HOME | `C:\OpenSSL-v3` |
| OCK_PATH | `C:\Users\Administrator\dev\OpenJDKDev\OCK` |
| DLL deployed to | `%JAVA_HOME%\bin\libjgskit_openssl_64.dll` |

---

## Git log (HEAD)

```
e7b398d  Enable sun.security.util.Debug in NativeOpenSSLAdapter, matching NativeOCKAdapter
54398ab  Scope AES PR: remove non-AES JNI C files, trim makefile and config to AES+SecureRandom only
ef4c2cf  Add @Tag(OPENJCEPLUS_OPENSSL_NAME) to 10 AES test classes; expand TestOpenJCEPlus to scan openjceplus package
6355362  Fix UTF-16 LE encoding in Digest.java and buildNativeWin64.bat, revert NativeOCKImplementation, add -Dskip.native.compile to test script
8bc77c1  Add openssl path (utils.groovy — Kostas)
191fcb6  Enable sysoout (pom.xml — Kostas)
1e502de  Apply PR1492 build/CI/multi-backend additions
f6d5575  Apply ojp_master working AES OpenSSL implementation
80085e1  Add openssl field (Kostas cherry-pick)
80f94db  Change cflags to link statically (Kostas cherry-pick)
ba00f78  Add to windows path (Kostas cherry-pick)
10df7d7  Update github actions (Kostas cherry-pick)
93a4657  Create OpenSSL java classes (Kostas cherry-pick)
b756660  Update test tags and method sources (Kostas cherry-pick)
9d53388  thu-ibm/main HEAD (base)
```

---

## Native files in scope (AES + SecureRandom only)

DLL built from 9 objects: `OpenSSLJNI`, `OpenSSLSymmetricCipher`, `OpenSSLGCM`, `OpenSSLCCM`,
`OpenSSLKeyWrap`, `OpenSSLRandom`, `OpenSSLUtils`, `OpenSSLHelpers`, `BuildDate`.

Removed from ojp_master (non-AES, belong in follow-on PRs):
- `OpenSSLSignature.c`, `OpenSSLKeyPairGenerator.c`, `OpenSSLDigest.c`
- `OpenSSLHMAC.c`, `OpenSSLHKDF.c`, `OpenSSLPBKDF2.c`
- `openssl_aes_random.win64.mak`, `buildNativeOpenSSL_AES_Random_Win64.bat`

---

## Test status

- `run_all_aes_tests.bat` → **10/10 PASSED** (148 test methods) — verified after every change
- `run_suite_openssl.bat` → **10/10 AES tests PASS** via TestOpenJCEPlus suite with `-Dgroups=OpenJCEPlus_OpenSSL`
- DLL rebuild: `buildNativeOpenSSL_Win64_AutoEnv.bat` → **BUILD SUCCESSFUL** (9 objects)
- PR#1492 new commits (`868b319`, `362532b`) — no-op for our branch (we already use `libcrypto-3-x64`)

---

## Working tree state

Untracked (not to be committed):
- `.idea/` — IDE files
- `internal-monologue/` — session notes
- `run_suite_openssl.bat` — local runner
- `src/main/native/libjgskit_openssl_64.dll` — build artifact

Modified but not staged (pre-existing upstream change, not ours):
- `src/main/native/openssl/OpenSSLUtils.h` — check before next commit

---

## What remains to do

1. **Run OCK regression suite** — prove AES OpenSSL changes don't break existing OCK path.
   - The `tests/` package uses `@ParameterizedClass` + `@MethodSource` which fails via `@Suite`,
     but works fine when run directly via `-Dtest=` or `-Dgroups=OpenJCEPlus`.
   - Command skeleton (needs correct `ock.library.path`):
     ```
     mvn test -Dgroups=OpenJCEPlus -Djgskit.library.path=C:\...\OCK -Dock.library.path=C:\...\OCK -Dskip.native.compile=true
     ```

2. **Push branch** to thu-ibm fork:
   ```
   git push origin openssl-aes
   ```

3. **Open PR**: `thu-ibm:openssl-aes` → `IBM/OpenJCEPlus:main`
   - Reference PR#1492 (`KostasTsiounis/openssl_backend`)
   - Title: "Add OpenSSL AES backend (GCM, CCM, KeyWrap) on top of PR#1492 test/build framework"

---

## Key files

| File | Purpose |
|------|---------|
| `run_all_aes_tests.bat` | Runs 10 AES tests directly |
| `run_suite_openssl.bat` | Suite runner with `-Dgroups=OpenJCEPlus_OpenSSL` |
| `buildNativeOpenSSL_Win64_AutoEnv.bat` | Builds `libjgskit_openssl_64.dll` |
| `src/main/native/openssl/openssl.win64.mak` | AES+Random Windows makefile |
| `src/test/ProviderOpenSSLAttrs.config` | AES Cipher + SecureRandom → OpenSSL backend |
| `src/test/java/ibm/jceplus/junit/openjceplus/` | 10 AES OpenSSL test classes |
| `src/main/java/.../openssl/NativeOpenSSLAdapter.java` | Main OpenSSL JNI adapter |
| `src/main/native/openssl/OpenSSLGCM.c` | AES-GCM C implementation |
