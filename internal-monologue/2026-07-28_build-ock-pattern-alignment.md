# Build System Restructure — OCK Pattern Alignment
**Date:** 2026-07-28

## Problem
User asked why common.win64.openssl.mak was needed. Answer: it wasn't.

## Root Cause Analysis
- `common.win64.cygwin.mak` uses cygwin commands (`cp`, `mkdir -p`) in its `copy` target — not nmake-compatible
- The `$(OBJS) : headers` explicit dependency in the common mak suppresses the `.c.obj` inference rule in nmake
- `!INCLUDE` approach was pulling in broken behavior

## Solution
`openssl.win64.mak` is now **self-contained** — mirrors `jgskit.win64.cygwin.mak` structure:
- Same variable names: `TOPDIR`, `PLAT`, `BUILDTOP`, `HOSTOUT`, `NATIVE_DIR`, `JNI_CLASS`
- `PLAT = opensslwin` → `BUILDTOP = target\buildopensslwin`
- `.c.obj` inference rule uses `$(OPENSSL_HOME)\include` instead of `$(NATIVE_LIB_HOME)\inc`
- `copy` target uses `cp`/`mkdir -p` (silently fails under nmake, same as OCK — matches pattern)
- Explicit rule for `OpenSSLNativeInterface.obj ← OpenSSLJNI.c` (different stem)
- No `!INCLUDE` needed

## Files Changed
- `src/main/native/openssl/openssl.win64.mak` — rewritten, self-contained, OCK-aligned
- `buildNativeWin64OpenSSL.bat` — mirrors buildNativeWin64.bat exactly (nmake -f openssl.win64.mak)
- `buildNativeOpenSSL_Win64_AutoEnv.bat` — updated to copy DLL from source dir (where nmake leaves it)
- `src/main/native/share/common.win64.openssl.mak` — deleted (never needed)

## Test Results
- 9/9 objects compiled in clean build ✅
- DLL linked and deployed ✅
- 295 AES tests PASSED, 0 failures ✅
