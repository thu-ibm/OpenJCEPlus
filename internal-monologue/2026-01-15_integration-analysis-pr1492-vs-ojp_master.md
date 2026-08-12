# Integration Analysis: PR1492 vs ojp_master
**Date:** 2026-01-15  
**Goal:** Merge working AES OpenSSL code from ojp_master into PR1492 branch (or vice versa), producing a single coherent branch.

---

## 1. High-Level Verdict

**Use ojp_master as the base. Clone PR1492's branch from GitHub and port ojp_master's changes onto it** — NOT the other way around.

Reason: PR1492 is upstream/public; ojp_master is a private working fork that has resolved every critical bug identified in the PR1492 review, completed the AES/CCM/GCM native C implementation, redesigned the JNI calling convention, and fixed the infrastructure. ojp_master is simply the better, more complete codebase.

However the target is the IBM/OpenJCEPlus repo. The cleanest outcome is:
- Clone `IBM/OpenJCEPlus:openssl_backend` branch locally
- Apply all ojp_master changes on top of that clone
- Result: a PR-ready branch that passes AES tests and has the upstream history

---

## 2. Dimension-by-Dimension Comparison

### 2a. Architecture / JNI Calling Convention

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| Context passing | `long osslContextId` threaded through every JNI call | `int fipsFlag` (0/1) threaded through every JNI call; context managed inside C |
| Context lifecycle | Java-side `OpenSSLContext` wrapping a `long` | Java-side `OpenSSLContext` wrapping a `long` (id from `initializeOpenSSL()`) |
| initializeOpenSSL | COMMENTED OUT — context ID hardcoded to 0 | WORKING — calls `NativeOpenSSLImplementation.initializeOpenSSL(bool)` |
| Native library name | `libopenjceplus.so` / `libopenjceplus_64.dll` | `libjgskit_openssl_64.dll` (Windows), `libopenjceplus.so` (Linux) |
| Library loader | Extended `NativeImplementation` base class | Self-contained in `NativeOpenSSLImplementation`, uses DEBUG flag not println |

The ojp_master design is cleaner: fipsFlag is passed per-call, the C code manages the OSSL_LIB_CTX internally. PR1492 never got past the stub — the osslContextId is always 0.

### 2b. NativeInterface.java

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| `create_GCM_context()` | parameterless only | ADDED: `create_GCM_context(int keySize)` overload — **required for OpenSSL to select AES-128/192/256-GCM** |
| `DIGEST_updateFastJNI` | present | present |
| `DIGEST_digest_and_reset(long, long, int)` | present | present |
| All others | identical | identical |

**Action:** Take ojp_master's NativeInterface.java (adds the keySize overload).

### 2c. NativeCryptoSelector.java

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| OpenSSL branch | throws `ProviderException("FIPS not supported")` if isFIPS, else calls `getInstance()` | always calls `getInstance()` non-FIPS (FIPS support deferred) |
| `opensslBackendFIPS` field | present | REMOVED |
| Error type for null/bad args | `ProviderException` | `ProviderException` (same) |
| Unknown attribute default | throws `ConfigurationException` | returns `Backend.OCK` (safe fallback) |
| Thread-safety of lazy init | NOT volatile — race condition | volatile fields, `synchronized getInstance()` |

**Action:** Take ojp_master's NativeCryptoSelector.java entirely.

### 2d. NativeOpenSSLAdapter.java

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| Size | ~1224 lines, pure delegation with `osslContext.getId()` | ~700 lines, actual logic for GCM/CCM (init+final inline), `fipsFlag` per call |
| GCM methods | Simple delegation: `NativeOpenSSLImplementation.do_GCM_xxx(osslContext.getId(), ...)` | REAL implementation: calls `GCM_init(fipsFlag, gcmCtx, ...)` then `GCM_encryptFinal(...)` with bounds checks |
| CCM methods | Simple delegation (stubs) | REAL implementation: calls `CCM_init(...)`, `CCM_encryptFinal(...)` |
| Unimplemented methods | Silently delegated (will crash at JNI level) | Explicitly throw `UnsupportedOperationException` |
| `do_GCM_checkHardwareGCMSupport` | Returns `NativeOpenSSLImplementation.do_GCM_checkHardwareGCMSupport(osslContext.getId())` (unimplemented native) | Returns `-1` (intentional — prevents FastJNI path) |
| `validateLibraryLocation()` | COMMENTED OUT | Working implementation (gated by system property) |
| `validateLibraryVersion()` | Always throws due to null return | No-op (correct for OpenSSL) |
| OCK constant names | Uses `VALUE_OCK_VERSION`, `VALUE_OCK_INSTALL_PATH` | Correctly uses `VALUE_OPENSSL_VERSION`, `VALUE_OPENSSL_INSTALL_PATH` |
| `System.out.println` debug | YES — many | NO — uses `DEBUG` flag writing to stderr only |
| Thread-safety of singleton | NOT synchronized in subclass | `synchronized getInstance()` |
| `create_GCM_context(int keySize)` | Missing (NativeInterface override missing) | PRESENT and IMPLEMENTED |
| HKDF | Delegated to (unimplemented) native | Implemented: stateless, stores algo in ThreadLocal |

**Action:** Take ojp_master's NativeOpenSSLAdapter.java entirely — it is the only working version.

### 2e. NativeOpenSSLImplementation.java

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| JNI signature style | `(long osslContextId, ...)` — context-per-call | `(int fipsFlag, ...)` — FIPS-flag-per-call |
| initializeOpenSSL | `initializeOSSL(boolean)` - stub | `initializeOpenSSL(boolean)` — REAL |
| GCM natives | `do_GCM_xxx(long osslContextId, long gcmCtx, ...)` | `GCM_init`, `GCM_update`, `GCM_encryptFinal`, `GCM_decryptFinal` — redesigned, matches C |
| CCM natives | `do_CCM_xxx(long osslContextId, ...)` | `CCM_init`, `CCM_update`, `CCM_encryptFinal`, `CCM_decryptFinal` — redesigned |
| CIPHER natives | `CIPHER_xxx(long osslContextId, ...)` | `CIPHER_xxx(int fipsFlag, ...)` |
| Key wrap | `CIPHER_KeyWraporUnwrap(long osslContextId, ...)` | `KEYWRAP_wrap(int fipsFlag, ...)` + `KEYWRAP_unwrap(...)` separated |
| HMAC | Original OCK-style API (update+doFinal with key each time) | Redesigned: `HMAC_create/init/update/doFinal/delete` |
| HKDF | Stateful context (unimplemented) | Stateless: `extract/expand/derive` one-shot natives |
| Signatures | Per-algorithm: `SIGNATURE_sign(osslContextId, digestId, pkeyId)` | Redesigned: `SIGNATURE_create/update/sign/verify/delete` |
| Key pair gen | `ECKEY_generate/RSAKEY_generate/...` (many separate) | `KEYPAIRGEN_generateRSA/EC/DSA/EdDSA/DH` unified |
| Library loading | Extends `NativeImplementation` base, `preloadOpenSSL/preloadOpenJCEPlusNative` | Self-contained, `preloadOpenSSL()` + `preloadJGskit()`, DEBUG-gated logging |
| loadIfExists | Inherited from NativeImplementation with System.out.println | Private method, uses DEBUG flag |

**Action:** Take ojp_master's NativeOpenSSLImplementation.java entirely. The API surface is completely different.

### 2f. Native C Library

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| Files | `Digest.c`, `Utils.c`, `Utils.h`, 4 makefiles | 19 C/H files: GCM, CCM, Symmetric, KeyWrap, Digest, Signature, KeyPairGen, HMAC, HKDF, PBKDF2, Random, Utils, Helpers, JNI, Context, ExceptionCodes, Logging |
| GCM | NOT IMPLEMENTED | IMPLEMENTED (`OpenSSLGCM.c`) |
| CCM | NOT IMPLEMENTED | IMPLEMENTED (`OpenSSLCCM.c`) |
| AES-CBC/CTR/ECB | NOT IMPLEMENTED | IMPLEMENTED (`OpenSSLSymmetricCipher.c`) |
| Key wrap | NOT IMPLEMENTED | IMPLEMENTED (`OpenSSLKeyWrap.c`) |
| Error handling | `throwOSSLException()` with vsprintf buffer overflow | `setPendingOpenSSLException()` with safe allocation + GlobalRef caching |
| Debug logging | `int debug = 0; // FIXME`, always prints to stderr | `OpenSSLLogging.h` macros, compile-time `OPENSSL_DEBUG` flag |
| osslCheckStatus | Wrong loop condition (`== 1` not `!= 0`) | `logOpenSSLError()` with `ERR_error_string_n`, correct |
| Library DLL name | `libopenjceplus_64.dll` | `libjgskit_openssl_64.dll` |
| Makefile | 4 platform makefiles in `src/main/native/openssl/`, uses shared `common.*.mak` | 2 Windows makefiles (`openssl.win64.mak`, `openssl_aes_random.win64.mak`), self-contained (no shared mak dependency) |
| JNI_OnLoad | NOT PRESENT | `OpenSSLJNI.c` — required for proper library registration |

**Action:** Take ALL of ojp_master's native C files. PR1492's C layer has critical bugs and missing implementations.

### 2g. OpenSSLException.java

| Aspect | PR1492 | ojp_master |
|--------|--------|-----------|
| Error codes | 4 codes (FIPS_INVALID, OCK_ATTACH, BAD_PADDING, UNSPECIFIED) | 50+ codes covering digest, cipher, HMAC, HKDF, PBKDF2, context, signature, keypairgen |
| C integration | `throwOSSLException(env, code, msg)` | `setPendingOpenSSLException(env, code, msg)` with GlobalRef cache |
| Constructors | `(String)`, `(String, Throwable)`, `(int)` | `(String)`, `(String, int)`, `(String, Throwable)` |

**Action:** Take ojp_master's OpenSSLException.java. Richer and properly integrated with C.

### 2h. OpenSSLContext.java

Both are essentially the same wrapper around a `long` + `boolean isFIPS`. PR1492 has it `public class`, ojp_master has it `public final class`. ojp_master adds a `toString()`.

**Action:** Use ojp_master's version (final, complete).

### 2i. GCMCipher.java, CCMCipher.java, AESGCMCipher.java

These are ONLY in ojp_master (modified from base). PR1492 does not touch them at all.

Key changes in ojp_master:
- `BufferFactory.CryptoBuffer` replaces `FastJNIBuffer` in ThreadLocals (prevents UnsatisfiedLinkError)
- `GCMHardwareFunctionPtr != -1` guard prevents FastJNI path on OpenSSL (which returns -1)
- `create_GCM_context(keySize)` call
- `freed` volatile flag prevents double-free in `GCMContextPointer`
- `isOpenSSL` flag + `initCalled` for AAD suppression
- `clearThreadLocalContext()` and `isOpenSSLBackend()` public methods
- AESGCMCipher: `finalCalled`/`singleShotFinalCalled` state guards, AAD concatenation fix, null-output NPE fix
- CCMCipher: `tempInput` sizing bug fix, BufferFactory

**Action:** Take ALL ojp_master cipher Java changes.

### 2j. Infrastructure / Build

| File | PR1492 | ojp_master |
|------|--------|-----------|
| `NativeImplementation.java` | New base class (System.out.println debug) | NOT needed (ojp_master doesn't use it) |
| `BufferFactory.java` | NOT present | NEW — critical for dual-backend |
| `OpenJCEPlus.java` | Not touched | provider name fix for `configure()` |
| `BasicRandom.java` | Not touched | constructor throws NativeException |
| `DHKeyAgreement.java` | Not touched | removes ConfigurationException catch |
| `NativeOCKAdapter.java` | Minor: adds println | adds `create_GCM_context(int keySize)` override |
| `buildNativeWin64.bat` | adds OPENSSL_HOME check + openssl build | separate `buildNativeOpenSSL_Win64_AutoEnv.bat` |
| `pom.xml` | adds ojplib dirs + openssl.library.path | NOT modified (ojp_master uses separate bat) |
| `ProviderOpenSSLAttrs.config` | NOT present | NEW — sets NativeProvider=OpenSSL for all services |
| `.github/workflows` | apt-get + manual header copy (fragile) | not modified (standalone bat builds) |
| `OCKOnly.config` | NEW test config | NOT present |
| `BaseTestAESGCMBufferIV.java` | not touched | tag length 16→32 bits fix |
| `BaseUtils.java`, `BaseTest.java` | not touched | OpenSSL provider reconfigure support |

---

## 3. Integration Strategy

### Recommended approach: Clone PR1492 branch, apply ojp_master on top

```
Step 1: Clone openssl_backend branch from IBM/OpenJCEPlus
        git clone --branch openssl_backend IBM/OpenJCEPlus target_repo

Step 2: Copy ALL files from ojp_master that are new/modified
        (see file list below)

Step 3: Remove PR1492-only files that are replaced by ojp_master
        (see removal list below)

Step 4: Build and verify: run_all_aes_tests.bat
```

### Files to TAKE FROM ojp_master (overwrite PR1492 version):

**Java - openssl package (complete replacement):**
- `src/main/java/.../openssl/NativeOpenSSLAdapter.java`
- `src/main/java/.../openssl/NativeOpenSSLAdapterFIPS.java`
- `src/main/java/.../openssl/NativeOpenSSLAdapterNonFIPS.java`
- `src/main/java/.../openssl/NativeOpenSSLImplementation.java`
- `src/main/java/.../openssl/OpenSSLContext.java`
- `src/main/java/.../openssl/OpenSSLException.java`

**Java - base package (overwrite/new):**
- `src/main/java/.../base/NativeInterface.java`  (adds create_GCM_context(int))
- `src/main/java/.../base/NativeCryptoSelector.java`  (working OpenSSL init)
- `src/main/java/.../base/BufferFactory.java`  (NEW — not in PR1492)
- `src/main/java/.../base/GCMCipher.java`
- `src/main/java/.../base/CCMCipher.java`
- `src/main/java/.../base/BasicRandom.java`

**Java - provider package:**
- `src/main/java/.../provider/AESGCMCipher.java`
- `src/main/java/.../provider/OpenJCEPlus.java`
- `src/main/java/.../provider/DHKeyAgreement.java`

**Java - OCK adapter:**
- `src/main/java/.../ock/NativeOCKAdapter.java`  (adds create_GCM_context(int) override)

**Native C (complete replacement of PR1492's openssl/ C files):**
- All 19 files from `src/main/native/openssl/`

**Build:**
- `src/main/native/openssl/openssl.win64.mak`
- `src/main/native/openssl/openssl_aes_random.win64.mak`
- `src/main/native/openssl/jgskit_resource.rc`
- `buildNativeOpenSSL_Win64_AutoEnv.bat`
- `buildNativeOpenSSL_AES_Random_Win64.bat`
- `run_all_aes_tests.bat`

**Test / Config:**
- `src/test/ProviderOpenSSLAttrs.config`
- `src/test/.../base/BaseTestAESGCMBufferIV.java`
- `src/test/.../base/BaseUtils.java`
- `src/test/.../tests/BaseTest.java`

### Files to REMOVE from PR1492 that are superseded:

- `src/main/java/.../base/NativeImplementation.java`  
  (ojp_master doesn't use this base class; loadIfExists is inlined into NativeOpenSSLImplementation)
- `src/main/native/openssl/Digest.c` (replaced by `OpenSSLDigest.c`)
- `src/main/native/openssl/Utils.c` (replaced by `OpenSSLUtils.c` + `OpenSSLHelpers.c`)
- `src/main/native/openssl/Utils.h` (replaced by `OpenSSLUtils.h` + `OpenSSLHelpers.h`)
- `src/main/native/openssl/openjceplus.mak`
- `src/main/native/openssl/openjceplus.mac.mak`
- `src/main/native/openssl/openjceplus.win64.mak`
- `src/main/native/openssl/openjceplus.win64.cygwin.mak`
- `src/main/native/openssl/openjceplus_resource.rc`

### Files to KEEP from PR1492 (unique, not in ojp_master):

- `.github/workflows/github-actions.yml` — keep but update openssl path section
- `Jenkinsfile` — keep (CI references to getOpenSSL)
- `buildNative.sh`, `buildNativeMac.sh`, `buildNativeWin64.bat` — keep with OPENSSL_HOME additions
- `pom.xml` — keep ojplib dir additions + openssl.library.path additions
- `src/main/native/share/common.*.mak` — keep (added include path + NATIVE_DIR)
- `src/test/OCKOnly.config` — keep (useful test artifact)
- `.gitignore` additions

### Shared common.*.mak note:

PR1492 modified the shared makefiles to output JNI headers to `$NATIVE_DIR` instead of hardcoded `ock/`. ojp_master's `openssl.win64.mak` is self-contained and doesn't use the shared makefiles. For Linux/Mac builds, the PR1492 shared makefile approach will be needed when adding Linux support.

---

## 4. Key API Incompatibility to Resolve

The biggest incompatibility is the **JNI calling convention**:

- PR1492 C stubs: `Java_..._DIGEST_create(JNIEnv*, jclass, jlong osslContextId, jstring algo)`
- ojp_master C impl: `Java_..._DIGEST_create(JNIEnv*, jclass, jint fipsFlag, jstring algo)`

The first argument after `(JNIEnv*, jclass)` is different: `jlong contextId` vs `jint fipsFlag`.

Since ojp_master's C files are what will be compiled, and its Java `NativeOpenSSLImplementation.java` declares `(int fipsFlag, ...)` signatures, the JNI function names will match — **no conflict**. The PR1492 Digest.c file must simply be deleted (replaced by `OpenSSLDigest.c`).

---

## 5. NativeOCKAdapterNonFIPS — debug println

PR1492 added `System.out.println("Using OCK non-FIPS adapter.")` to `NativeOCKAdapterNonFIPS.getInstance()`. This is NOT in ojp_master and should NOT be carried forward. When taking ojp_master's NativeCryptoSelector, it calls the original OCK path which goes through the unchanged OCK adapter — confirm that NativeOCKAdapterNonFIPS.java is left as it was in main (no println).

---

## 6. pom.xml additions needed

ojp_master does NOT modify pom.xml. PR1492 adds `build.target.ojplib.dir` for each platform profile and `openssl.library.path`/`openjceplus.library.path` system properties. These additions are still needed in the combined branch for Maven-based builds to find the native library. Keep PR1492's pom.xml changes.

However the `openjceplus.library.path` property in PR1492 maps to the `ojp-*` output dirs which are for `libopenjceplus.so`. ojp_master uses `libjgskit_openssl_64.dll`/`libjgskit_openssl_64.so`. The property name should be `jgskit.library.path` (which ojp_master's `NativeOpenSSLImplementation.getJGskitLoadPath()` already checks) OR rename consistently. Easiest: add BOTH `jgskit.library.path` and keep `openssl.library.path` pointing to the same dir.

---

## 7. Next Steps for New Task

When starting the integration task:
1. `git clone` or `git checkout` the `openssl_backend` branch of IBM/OpenJCEPlus
2. Copy files from ojp_master per the lists above (use robocopy or xcopy for bulk copy)
3. Delete the superseded PR1492 files
4. Reconcile pom.xml: keep PR1492 additions, rename `openjceplus.library.path` → also support `jgskit.library.path`
5. Build: `buildNativeOpenSSL_Win64_AutoEnv.bat` (Windows)
6. Run: `run_all_aes_tests.bat`
7. Fix any remaining integration issues (likely: library path property name, pom.xml profile output dirs)

---

## 8. Why NOT to use ojp_master as-is

ojp_master is a standalone working repo but:
- It doesn't have the PR1492 upstream history
- It doesn't have the multi-platform build infrastructure (Linux/Mac makefiles from PR1492)
- It doesn't have the CI workflow updates
- Its `openssl.win64.mak` is standalone (doesn't use shared `common.*.mak`)

The goal is to get this merged into IBM/OpenJCEPlus, so we need to work on the PR1492 branch and bring ojp_master's good work onto it.
