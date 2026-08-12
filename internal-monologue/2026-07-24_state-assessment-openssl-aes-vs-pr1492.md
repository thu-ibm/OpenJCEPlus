# State Assessment: openssl_aes vs PR1492
**Date:** 2026-07-24

## Summary

User confirmed that `c:\Users\Administrator\openjdk_dev\openssl_aes\` is the `thu-ibm/OpenJCEPlus:main` clone
that serves as the working directory for the next integration task (equivalent to `thu_main` from the prior plan).

## git remote
- `origin` → `git@github.com:thu-ibm/OpenJCEPlus.git`
- Branch: `main` (latest commit: `9d53388 Add OpenJCEPlusFIPS to module-info.java`)

## git status pattern (identical to post-integration PR1492)
Modified tracked files (same set as ojp_master integration):
- `.github/workflows/github-actions.yml`, `Jenkinsfile`, `buildNative.sh`, `buildNativeMac.sh`, `buildNativeWin64.bat`, `pom.xml`
- `AESGCMCipher.java`, `DHKeyAgreement.java`, `OpenJCEPlus.java`
- `base/BasicRandom.java`, `base/CCMCipher.java`, `base/GCMCipher.java`, `base/NativeCryptoSelector.java`, `base/NativeInterface.java`
- `ock/NativeOCKAdapter.java`
- `src/main/native/share/common.*.mak` (4 files)
- Test files: `BaseTestAESGCMBufferIV.java`, `BaseUtils.java`, `BaseTest.java`

Untracked new files:
- `buildNativeOpenSSL_AES_Random_Win64.bat`
- `buildNativeOpenSSL_Win64_AutoEnv.bat`
- `run_all_aes_tests.bat`
- `src/main/java/.../base/BufferFactory.java`
- `src/main/java/.../openssl/` (entire openssl package)
- `src/main/native/libjgskit_openssl_64.dll`
- `src/main/native/openssl/` (all 25 C/H/mak files)
- `src/test/ProviderOpenSSLAttrs.config`

## Assessment
All integration files from ojp_master have been applied to openssl_aes (same pattern as the completed
PR1492 integration from 2026-07-23). The DLL is present as a pre-built binary.

## What still needs to be done
1. Confirm DLL is deployed to `%JAVA_HOME%\bin\`
2. Run `run_all_aes_tests.bat` from `openssl_aes\` directory
3. If tests pass → commit and optionally push
4. If tests fail → diagnose and fix

## Key paths
- JAVA_HOME: `C:\Users\Administrator\Downloads\opensdk\semeru\jdk`
- OPENSSL_HOME: `C:\OpenSSL-v3`
- DLL target: `%JAVA_HOME%\bin\libjgskit_openssl_64.dll`
