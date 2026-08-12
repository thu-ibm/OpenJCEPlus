# Scope AES PR: Remove Non-AES JNI C Files
**Date:** 2026-07-27

## What was done

Removed 6 non-AES JNI C files that came in via ojp_master commit (f6d5575):
- `OpenSSLSignature.c` (RSA/ECDSA/EdDSA/DSA — 965 lines)
- `OpenSSLKeyPairGenerator.c` (RSA/EC/DSA/EdDSA/DH — 964 lines)
- `OpenSSLDigest.c` (SHA-1/SHA-2/SHA-3 — 544 lines)
- `OpenSSLHMAC.c` (459 lines)
- `OpenSSLHKDF.c` (662 lines)
- `OpenSSLPBKDF2.c` (243 lines)

Also removed:
- `openssl_aes_random.win64.mak` — superseded by trimmed `openssl.win64.mak`
- `buildNativeOpenSSL_AES_Random_Win64.bat` — superseded

**Kept `OpenSSLRandom.c`** — required for SecureRandom (SHA256/512DRBG) registered via
`ProviderOpenSSLAttrs.config`. The provider must be at position 1 for `new SecureRandom()`
to work correctly during tests.

Trimmed `ProviderOpenSSLAttrs.config` — removed Digest, HMAC, Signature, KeyPairGen,
PBKDF2, HKDF entries. Now only AES Ciphers + SecureRandom remain.

Trimmed `openssl.win64.mak` — removed the 6 deleted object targets.

## Result
- Committed as `54398ab`
- DLL rebuilt: 9 object files, BUILD SUCCESSFUL
- All 10 AES tests: PASS (148 test methods)

## Git log
```
54398ab  Scope AES PR: remove non-AES JNI C files, trim makefile and config to AES+SecureRandom only
ef4c2cf  Add @Tag(OPENJCEPLUS_OPENSSL_NAME) to 10 AES test classes; expand TestOpenJCEPlus to scan openjceplus package
...
```
