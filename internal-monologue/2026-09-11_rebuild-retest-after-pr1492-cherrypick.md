# Rebuild and retest after PR 1492 cherry-picks

## Problem
After cherry-picking 4 commits from PR 1492 and running `git cherry-pick --skip`,
all untracked dev files (*.bat scripts, *.txt outputs, native *.c signature files) were wiped.

## Recovery
Restored all missing files from D:\Ddev\new_backup\thu_main:
- Dev scripts: run_suite_openssl.bat, buildNativeOpenSSL_Win64_AutoEnv.bat, etc.
- Native C files: OpenSSLSignature.c, OpenSSLDSAKey.c, OpenSSLECKey.c, OpenSSLRSAKey.c, OpenSSLRSAPSS.c, OpenSSLXECKey.c
- Test files: TestEdDSASignature.java, TestRSAPSS.java
- Output/temp files: suite_out*.txt, build_openssl.txt, etc.

## Compilation fix
The cherry-picked `e0e1440e` commit added `loadIfExists(File)` to `NativeOCKImplementation`
as `private`, but the parent `NativeImplementation` already declares it `protected`.
Since the parent's version is identical, removed the duplicate override from `NativeOCKImplementation`.

## Build result
buildNativeOpenSSL_Win64_AutoEnv.bat → BUILD SUCCESSFUL
DLL copied to C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin\

## Test result
run_suite_openssl.bat → TestOpenJCEPlus suite (OpenSSL_OpenSSL tag)
Tests run: 1147, Failures: 0, Errors: 0, Skipped: 36
BUILD SUCCESS
