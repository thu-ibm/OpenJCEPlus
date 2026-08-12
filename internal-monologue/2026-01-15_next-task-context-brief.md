# Context Brief for Next Task
**Date:** 2026-01-15  
**Prepared by:** Bob (carry-forward from prior task sessions)

---

## What has been done so far

### Session 1 — PR Review
- Reviewed IBM/OpenJCEPlus PR #1492 (`openssl_backend` branch by KostasTsiounis)
- PR adds OpenSSL backend scaffolding but is non-functional: context hardcoded to 0, no AES C implementations, multiple critical bugs
- Full review artifact saved; 13 findings documented

### Session 2 — Deep Analysis
- Analysed `ojp_master/` (a private working fork in this workspace at `c:\Users\Administrator\openjdk_dev\PR1492\ojp_master\`)
- ojp_master has WORKING AES OpenSSL implementation: GCM, CCM, Symmetric, KeyWrap all pass 147 test methods
- Full file-by-file comparison between PR1492 and ojp_master documented in:
  `internal-monologue/2026-01-15_integration-analysis-pr1492-vs-ojp_master.md`

### Session 3 — Integration (PR1492 ← ojp_master)
- Cloned `IBM/OpenJCEPlus:openssl_backend` into `c:\Users\Administrator\openjdk_dev\PR1492\`
- Applied ojp_master's working AES code on top
- Rebuilt `libjgskit_openssl_64.dll` from source — clean build, zero errors
- DLL: 116,736 bytes, deployed to `%JAVA_HOME%\bin\`

---

## The new problem

`IBM/OpenJCEPlus:openssl_backend` (PR1492 base) is itself outdated relative to `thu-ibm/OpenJCEPlus:main`.  
The correct upstream base for the next round of work is:

**`https://github.com/thu-ibm/OpenJCEPlus/tree/main`**

---

## What the next task must do

1. **Clone `thu-ibm/OpenJCEPlus:main`** into a fresh working directory (suggest `c:\Users\Administrator\openjdk_dev\thu_main\`)
2. **Diff** it against both ojp_master and the current PR1492 workspace to understand what `thu-ibm:main` already has
3. **Apply** the necessary OpenSSL backend files from both sources on top of `thu-ibm:main`
4. **Build and test** — all AES tests must pass

---

## Source locations (all on this machine)

| Source | Path | Branch/State |
|--------|------|-------------|
| thu-ibm upstream (to clone) | `https://github.com/thu-ibm/OpenJCEPlus` | `main` |
| ojp_master (working AES) | `c:\Users\Administrator\openjdk_dev\PR1492\ojp_master\` | git main, uncommitted changes |
| Current PR1492 workspace | `c:\Users\Administrator\openjdk_dev\PR1492\` | openssl_backend, ojp_master applied |
| Other dev copies | `c:\Users\Administrator\openjdk_dev\` | various (native_selector*, IBM_OpenJCEPlus, etc.) |

---

## Key files from ojp_master to carry forward

Read `internal-monologue/2026-01-15_integration-analysis-pr1492-vs-ojp_master.md` for the full list.  
Short version — these are the files ojp_master contributes that are NOT in any upstream:

### New Java files (not in any upstream IBM repo):
- `src/main/java/.../openssl/NativeOpenSSLAdapter.java` — working GCM/CCM, fipsFlag convention
- `src/main/java/.../openssl/NativeOpenSSLAdapterFIPS.java` — FIPS placeholder
- `src/main/java/.../openssl/NativeOpenSSLAdapterNonFIPS.java` — synchronized singleton
- `src/main/java/.../openssl/NativeOpenSSLImplementation.java` — fipsFlag JNI, real initializeOpenSSL
- `src/main/java/.../openssl/OpenSSLContext.java` — final, complete
- `src/main/java/.../openssl/OpenSSLException.java` — 50+ error codes
- `src/main/java/.../base/BufferFactory.java` — backend-agnostic buffer (prevents UnsatisfiedLinkError)

### Modified Java files (ojp_master has better versions than either upstream):
- `base/NativeInterface.java` — adds `create_GCM_context(int keySize)` overload
- `base/NativeCryptoSelector.java` — volatile, lazy OpenSSL init, safe fallback
- `base/GCMCipher.java` — BufferFactory, FastJNI guard, keySize, double-free fix, AAD suppression
- `base/CCMCipher.java` — BufferFactory, FastJNI guard, tempInput sizing fix
- `base/BasicRandom.java` — constructor throws NativeException
- `provider/AESGCMCipher.java` — state guards, AAD concat fix, null-output NPE fix
- `provider/OpenJCEPlus.java` — provider name fix for configure()
- `provider/DHKeyAgreement.java` — removes ConfigurationException catch
- `ock/NativeOCKAdapter.java` — adds create_GCM_context(int keySize) override

### New native C files (not in any upstream):
All files in `ojp_master/src/main/native/openssl/`:
- OpenSSLGCM.c/.h, OpenSSLCCM.c, OpenSSLSymmetricCipher.c/.h, OpenSSLKeyWrap.c
- OpenSSLDigest.c, OpenSSLSignature.c, OpenSSLKeyPairGenerator.c
- OpenSSLHMAC.c, OpenSSLHKDF.c, OpenSSLPBKDF2.c, OpenSSLRandom.c
- OpenSSLJNI.c, OpenSSLHelpers.c/.h, OpenSSLUtils.c/.h
- OpenSSLContext.h, OpenSSLExceptionCodes.h, OpenSSLLogging.h
- BuildDate.c
- openssl.win64.mak, openssl_aes_random.win64.mak, jgskit_resource.rc

### New build/test files (from ojp_master):
- `buildNativeOpenSSL_Win64_AutoEnv.bat` — auto-detects VS, builds DLL
- `buildNativeOpenSSL_AES_Random_Win64.bat` — AES-only subset build
- `run_all_aes_tests.bat` — runs 10 AES test classes with -Dopenjceplus.useOpenSSL=true
- `src/test/ProviderOpenSSLAttrs.config` — sets NativeProvider=OpenSSL for all services

### Modified test files (from ojp_master):
- `BaseTestAESGCMBufferIV.java` — GCM tag 16 bits → 32 bits
- `BaseUtils.java` — OpenSSL provider reconfigure
- `BaseTest.java` — OpenSSL provider reconfigure, insertion pos 0→1

---

## Key files from PR1492 to carry forward

These are unique to PR1492 and NOT in ojp_master — they add multi-platform and CI support:

- `pom.xml` additions: `build.target.ojplib.dir` per platform profile, `openssl.library.path`/`openjceplus.library.path`/`jgskit.library.path` system properties
- `buildNative.sh` additions: OPENSSL_HOME check + openssl makefile invocation (Linux)
- `buildNativeMac.sh` additions: same for Mac
- `buildNativeWin64.bat` additions: OPENSSL_HOME check
- `src/main/native/share/common.*.mak` (4 files): `-I${NATIVE_LIB_HOME}/include` + NATIVE_DIR header output
- `.github/workflows/github-actions.yml`: apt-get libssl-dev, header copy, OPENSSL_HOME env vars
- `Jenkinsfile`: getOpenSSL() call
- `src/test/OCKOnly.config`: OCK-only test fixture
- `.gitignore` additions: openssl JNI header patterns

---

## Files to EXCLUDE (PR1492-only, superseded by ojp_master)

Do NOT carry these forward — they were deleted or replaced:
- `NativeImplementation.java` (base class — ojp_master doesn't use it)
- `Digest.c`, `Utils.c`, `Utils.h` (replaced by OpenSSLDigest.c, OpenSSLHelpers, OpenSSLUtils)
- `openjceplus.mak`, `openjceplus.mac.mak`, `openjceplus.win64.mak`, `openjceplus.win64.cygwin.mak`
- `openjceplus_resource.rc`

---

## Critical technical facts

### JNI calling convention (ojp_master wins)
- ojp_master: `(int fipsFlag, ...)` — C manages OSSL_LIB_CTX internally
- PR1492: `(long osslContextId, ...)` — context never initialized (always 0)
- **Use ojp_master's convention throughout**

### Native library name
- ojp_master: `libjgskit_openssl_64.dll` (loaded via `jgskit.library.path` or `openssl.library.path`)
- PR1492: `libopenjceplus_64.dll` (via `openjceplus.library.path`)
- **Use ojp_master's name**. In pom.xml ensure `jgskit.library.path` points to the build output dir.

### Build output directory
- ojp_master makefile outputs to: `target\buildopensslwin\host64\`
- PR1492 pom.xml profiles use: `target\ojp-xa-64\` etc.
- Both need to be wired up — pom.xml should set `jgskit.library.path=${build.target.ojplib.dir}` AND point that dir to `target\buildopensslwin\host64\` on Windows.

### OpenSSL version
- `C:\OpenSSL-v3\` — OpenSSL 3.x installed on this machine
- `OPENSSL_HOME=C:\OpenSSL-v3`
- `JAVA_HOME=C:\Users\Administrator\Downloads\opensdk\semeru\jdk`

### Test verification command
```
run_all_aes_tests.bat
```
Expected: 10/10 test classes pass, 147 individual test methods.
System property: `-Dopenjceplus.useOpenSSL=true`
Config: `src/test/ProviderOpenSSLAttrs.config`

---

## What thu-ibm:main may already have

**Unknown** — needs to be checked when cloned. It may already have:
- Some or all of the NativeCryptoSelector / NativeInterface changes from PR1492
- Provider config infrastructure updates
- Test framework updates

**The first thing to do after cloning** is run `git diff` or file-compare against the known good ojp_master files to identify what's already there vs. what still needs to be added.

---

## Suggested working directory for next task

`c:\Users\Administrator\openjdk_dev\thu_main\`

Clone command:
```
git clone https://github.com/thu-ibm/OpenJCEPlus c:\Users\Administrator\openjdk_dev\thu_main
```

---

## Definition of done for next task

1. `thu-ibm:main` cloned into fresh directory
2. All ojp_master + necessary PR1492 files applied on top
3. `libjgskit_openssl_64.dll` built from source with zero errors
4. `run_all_aes_tests.bat` — all 10 AES test classes pass
5. `internal-monologue/` updated with what was done
