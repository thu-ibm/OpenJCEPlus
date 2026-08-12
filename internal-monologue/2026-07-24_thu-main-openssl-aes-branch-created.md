# thu_main openssl-aes branch created and tested
**Date:** 2026-07-24

## What was done

### Strategy decision
- User owns ojp_master code (working AES OpenSSL implementation) but NOT KostasTsiounis/openssl_backend (PR#1492)
- Correct approach: fork thu-ibm/OpenJCEPlus, cherry-pick Kostas's commits, apply ojp_master on top

### Steps executed

1. **Fresh clone** of `git@github.com:thu-ibm/OpenJCEPlus.git` into `c:\Users\Administrator\openjdk_dev\thu_main`
   - HEAD: `9d533884` (includes the module-info.java FIPS registration — the 1 commit PR#1492 was missing)

2. **Created branch** `openssl-aes` from `main`

3. **Added Kostas remote** and fetched `openssl_backend`
   - Discovered 6 commits (not 5 as previously counted — `86a3a25 Add openssl field` was new)

4. **Cherry-picked all 6 Kostas commits** in order, zero conflicts:
   - `b756660` Update test tags and method sources (52 files, 5 new parameter resolver classes)
   - `93a4657` Create OpenSSL java classes (50 files, scaffold + OCKOnly/OpenSSLOnly configs)
   - `10df7d7` Update github actions
   - `ba00f78` Add to windows path
   - `80f94db` Change cflags to link statically
   - `80085e1` Add openssl field

5. **Applied ojp_master working AES implementation** — committed as `f6d5575`:
   - 17 modified Java files (AESGCMCipher, GCMCipher, CCMCipher, NativeOpenSSLAdapter, etc.)
   - 2 new Java files (BufferFactory.java, NativeOpenSSLAdapterFIPS.java)
   - 25 new C/H/mak native files (OpenSSLGCM, OpenSSLCCM, OpenSSLSymmetricCipher, etc.)
   - Deleted 9 files (Kostas's placeholder Digest.c, Utils.c, openjceplus*.mak, NativeImplementation.java)
   - 3 build/test scripts + ProviderOpenSSLAttrs.config

6. **Built DLL**: `buildNativeOpenSSL_Win64_AutoEnv.bat` — BUILD SUCCESSFUL, zero errors
   - Output: `target\buildopensslwin\host64\libjgskit_openssl_64.dll`
   - Deployed to `C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin\`

7. **Ran AES tests**: `run_all_aes_tests.bat` — **10/10 PASSED**
   - TestAES256Interop: 18 tests
   - TestAESKeyWrap: 64 tests
   - TestAESGCMUpdate: 20 tests
   - TestAESGCMWithKeyAndIvCheck: 1 test
   - TestAESGCMUpdateInteropBC: 3 tests
   - TestAESGCMBufferIV: 1 test
   - TestAESGCM_ExtIV: 28 tests
   - TestAESGCM_IntIV: 8 tests
   - TestAESCCMParameters: 3 tests
   - TestAESCCMInteropBC: 2 tests

## Final branch state
```
f6d5575  ojp_master: working AES OpenSSL implementation
80085e1  Kostas: add openssl field
80f94db  Kostas: change cflags to link statically
ba00f78  Kostas: add to windows path
10df7d7  Kostas: update github actions
93a4657  Kostas: create OpenSSL java classes
b756660  Kostas: update test tags and method sources
9d533884  thu-ibm/main HEAD (base)
```

## Next steps
- Push branch to thu-ibm fork: `git push origin openssl-aes`
- Open PR from `thu-ibm/OpenJCEPlus:openssl-aes` → `IBM/OpenJCEPlus:main`
