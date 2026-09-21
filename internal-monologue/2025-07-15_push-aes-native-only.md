# 2025-07-15 Push AES native files only to thu/openssl-aes

## Committed and pushed
12 AES-related native files only:
- OpenSSLCCM.c, OpenSSLGCM.c, OpenSSLSymmetricCipher.c, OpenSSLJNI.c, OpenSSLUtils.c
- OpenSSLContext.h, OpenSSLExceptionCodes.h, OpenSSLHelpers.h, OpenSSLUtils.h
- openjceplus.mak, openjceplus.win64.mak, openjceplus.win64.cygwin.mak

## Deliberately excluded (untracked, signature-related)
OpenSSLDSAKey.c, OpenSSLECKey.c, OpenSSLRSAKey.c, OpenSSLRSAPSS.c,
OpenSSLSignature.c, OpenSSLXECKey.c, and all .obj/.dll build artifacts.

## Push result
639483e3..ef54927f  thu/openssl-aes -> thu/openssl-aes
