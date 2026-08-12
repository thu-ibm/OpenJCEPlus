# PR #1492 Review: OpenSSL Backend

**Date:** 2025-01-15
**PR:** https://github.com/IBM/OpenJCEPlus/pull/1492
**Author:** KostasTsiounis
**Branch:** openssl_backend → main

## Summary
The PR introduces an OpenSSL native backend alongside the existing OCK backend.
Key files: NativeOpenSSLAdapter, NativeOpenSSLImplementation, NativeOpenSSLAdapterNonFIPS, OpenSSLContext, OpenSSLException, Digest.c, Utils.c, makefiles.

## Issues Found
- Multiple System.out.println debug prints left in production code
- NativeOpenSSLAdapterNonFIPS.getInstance() is not thread-safe
- initializeOSSL call is commented out; osslContextId hardcoded to 0
- validateLibraryLocation() body is entirely commented out
- DIGEST_digest calls EVP_DigestFinal_ex twice (probe for length then final)
- osslCheckStatus() ERR_get_error loop condition is wrong (== 1 instead of != 0)
- Utils.c uses fixed-size static print buffers (vsprintf overflow risk)
- int debug = 0; in Utils.c is a FIXME placeholder
- Digest.java: getContext() race — runtimeContextNum lookup after contexts check
- common.win64.mak uses mixed path separators (forward slash in HOSTOUT, backslash in include)
- Copyright year "2026" in newly added files
- NativeOCKAdapterNonFIPS.getInstance() also has a debug println added
