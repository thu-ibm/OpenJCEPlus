# 2025-07-15 Fix OpenSSLDSAKey.c comment, rebuild DLL

## Issue
Build failed on `OpenSSLDSAKey.c` line 447 with MSVC errors:
- `C2143`: syntax error (missing `{` before `*`) — caused by `*/` inside a block comment prematurely ending it
- `C2018`: unknown character `0x40` (`@`) — MSVC rejects `@param`/`@return` Javadoc-style tags in C comments

## Fix
In `src/main/native/openssl/OpenSSLDSAKey.c` around line 447:
- Changed `EVP_DigestSign*/EVP_DigestVerify*` → `EVP_DigestSign* / EVP_DigestVerify*`
- Changed em-dash `—` → `-`
- Removed `@` from `@param`/`@return` tags

## Result
`buildNativeOpenSSL_Win64_AutoEnv.bat` succeeded. DLL rebuilt and copied to JVM bin.
