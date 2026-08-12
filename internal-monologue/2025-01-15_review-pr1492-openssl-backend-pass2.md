# PR #1492 Review Pass 2: OpenSSL Backend (Additional Findings)

**Date:** 2025-01-15
**PR:** https://github.com/IBM/OpenJCEPlus/pull/1492

## New Issues Found in Pass 2

### Java – NativeImplementation.java
1. **System.out.println in loadIfExists()** (lines 353, 361, 368, 374): 4 bare `System.out.println` calls
   in the newly extracted base class `NativeImplementation.loadIfExists()`. The OCK version of this method
   had none of these prints; they were added during the refactor. Debug output belongs behind the `debug != null`
   guard already present.

### Java – NativeOpenSSLAdapterNonFIPS.java
2. **`getInstance()` not thread-safe**: The `instance == null` check is unsynchronised. If two threads call
   it simultaneously both can create an instance. The OCK counterpart has the same problem but it was
   pre-existing; here it is a new class.

3. **`System.out.println("Using OpenSSL non-FIPS adapter.")` before the null check** (line 1690): printed
   on every call, not just the first instantiation.

### Java – NativeOpenSSLAdapter.java
4. **`initialize()` always returns 0 / `initializeOSSL` commented out** (line 716-717): The
   `NativeInterface.initialize()` override silently returns a fake context ID of 0. Callers cannot
   distinguish "not yet initialised" from a valid context. This is the same as the `initializeContext()`
   issue already flagged in pass 1, but it is a separate entry point that silently no-ops.

5. **`libraryBuildDate` is a `static` field** (line 487): shared across all adapter instances. If a second
   adapter with a different native library is created the cached value from the first one will be returned.
   Should be an instance field (like `osslVersion` / `osslInstallPath`).

6. **`getLibraryBuildDate()` — double semicolon** (line 709):
   `libraryBuildDate = NativeOpenSSLImplementation.getLibraryBuildDate();;`

7. **`validateLibraryVersion()` uses OCK-named constant names** (lines 679-681): comments and path
   construction use `"icclib"`, `"ICCSIG.txt"`, `"# ICC Version"` — clearly OCK-sourced code that was
   pasted verbatim and not updated for OpenSSL.

8. **`VALUE_OCK_INSTALL_PATH` / `VALUE_OCK_VERSION` constant names** (lines 463-465): these are
   OpenSSL-context value IDs but named after OCK (`OCK`). Should be renamed to
   `VALUE_OSSL_INSTALL_PATH` / `VALUE_OSSL_VERSION`.

9. **`obtainOpenSSLVersion()` / `obtainOpenSSLInstallPath()` use OCK constant names** (lines 599, 609):
   `CTX_getValue(VALUE_OCK_VERSION)` / `CTX_getValue(VALUE_OCK_INSTALL_PATH)`.

10. **`getOpenSSLContext()` double-checked locking incomplete** (lines 569-573): `osslInitialized` flag
    is read without synchronisation inside `getOpenSSLContext()`, but the write happens inside
    `initializeContext()` which is `synchronized`. The unsynchronised read is not guaranteed to see the
    write on all JVMs (missing `volatile`).

### Java – NativeOpenSSLImplementation.java
11. **`requirePreloadOSSL` is package-visible mutable `static`** (line 1731): `static boolean
    requirePreloadOSSL = true;` — mutable from any class in the package. Should be `private static
    final`.

12. **`osName` / `osArch` set in multiple methods** (lines 1764, 1824, 1840): `getOSSLLoadFile()`,
    `getOpenJCEPlusNativeLoadPath()`, and `preloadOpenJCEPlusNative()` all re-query and overwrite the
    static `osName`/`osArch`. Concurrent initialisation could cause races or incorrect values.

13. **`preloadOpenSSL()` trailing blank line + unnecessary whitespace** (line 1860): minor style but
    inconsistent with the surrounding code.

14. **`getExpectedLibraryVersion()` always returns `null`** (lines 672-703): the entire body is commented
    out, so `validateLibraryVersion()` will always throw
    `"Could not not determine expected version"` (also has a double `"not not"`). Either the method should
    be wired up or `validateLibraryVersion()` must not be called when the version can't be obtained.

### C – Digest.c
15. **`DIGEST_digest` calls `EVP_DigestFinal_ex(mdCtx, NULL, ...)` first to probe length** (line 2824):
    `EVP_DigestFinal_ex` finalises the digest state; calling it a second time (line 2843) with the real
    buffer is undefined behaviour. The correct way to query the output size is `EVP_MD_CTX_get_size()`.

16. **`DIGEST_digest_and_reset`: `digestLen` initialised to 0** (line 2934, 2947): passed as `digestLen`
    to `DIGEST_digest_and_reset_internal()` without being set to the actual digest size. The call to
    `EVP_DigestFinal_ex(mdCtx, digestBytesNative, &digestLen)` will write into the caller-provided buffer
    using a 0-length hint on some OpenSSL builds.

17. **`DIGEST_reset` error message says "DIGEST_size"** (line 3000):
    `throwOSSLException(env, 0, "DIGEST_size: The specified mdCtx is null")` — wrong function name in
    the error string.

18. **`EVP_MD_free(md)` called before `ReleaseStringUTFChars`** (lines 2657-2660): if
    `ReleaseStringUTFChars` is not called (e.g. on the goto-cleanup path where digestAlgoChars might be
    NULL), there is a potential release of a null pointer. However `GetStringUTFChars` returns NULL on
    failure and is correctly checked, so `digestAlgoChars` may be NULL here — `ReleaseStringUTFChars`
    with a NULL `chars` pointer is technically undefined.

### C – Utils.c
19. **`osslCheckStatus()` while-loop condition `== 1` should be `!= 0`** (line 3150):
    `while ((errCode = ERR_get_error()) == 1)` — `ERR_get_error()` returns 0 when the error queue is
    empty; it never returns exactly `1` for a real error. The loop exits immediately on any real error
    code ≠ 1.

20. **`vsprintf` with fixed 4096-byte buffers — overflow risk** (lines 3066, 3084, 3102):
    `static char printBuffer[4096]` used with `vsprintf`. If the formatted string exceeds 4096 bytes a
    buffer overflow occurs. Should use `vsnprintf`.

21. **`static` print buffers in `gslogError/gslogMessage/gslogMessagePrefix` are not thread-safe**
    (same lines): shared `static char printBuffer[4096]` across calls from multiple threads.

### Build files
22. **`common.win64.mak` mixes path separators** (line 3566):
    `-I"$(NATIVE_LIB_HOME)\include"` uses a backslash while the other `-I` flags on adjacent lines use
    forward slashes. Inconsistent and can break some toolchains.

23. **`openjceplus.win64.mak` uses forward slashes for `HOSTOUT`** (line 3429):
    `HOSTOUT = $(BUILDTOP)/ojp-host64` while the companion `openjceplus.win64.cygwin.mak` uses
    backslashes. The `.mak` variant is for MSVC not Cygwin and should use backslashes consistently.

### CI / GitHub Actions
24. **Headers copied with `cp /usr/include/x86_64-linux-gnu/openssl/* .`** (line 15): this step is
    unconditional and will fail on non-x86 GitHub runners (ARM, etc.). Should be guarded or use
    `dpkg` install paths dynamically.

### Miscellaneous
25. **`OpenSSLException` error-code map is incomplete** (line 3551): `GKR_DECRYPT_FINAL_BAD_PADDING_ERROR`
    (`0x00000003`) and `GKR_UNSPECIFIED` (`0x80000000`) are defined as constants but not added to
    `buildErrorCodeMap()`. Their `errorMessage()` fallback silently returns a hex string.

26. **`OpenSSLContext.createContext()` declares `throws OpenSSLException`** (line 2491) but its body
    never throws one; the checked exception is unnecessary and forces callers to handle it.

27. **`NativeOpenSSLAdapter.providerException()` is `static public`** (line 613): visibility is too wide;
    it is only used internally. Should be `private static` or at most `protected static`.

28. **`do_GCM_FinalForUpdateDecrypt` commented-out parameters** (lines 2045-2046):
    `/* byte[] key, int keyLen, byte[] iv, int ivLen, */` — dead code in a public native method
    declaration. Suggests the signature is provisional and not final.

## Previously-flagged Issues (Confirmed Still Present)
- Multiple `System.out.println` debug prints in `NativeImplementation.loadIfExists()` (new in this PR,
  previously flagged for NativeOpenSSLAdapterNonFIPS and NativeOCKAdapterNonFIPS).
- `initializeOSSL` call commented out; `osslContextId` hardcoded to 0.
- `validateLibraryLocation()` body entirely commented out.
- `osslCheckStatus()` loop condition wrong.
- `vsprintf` overflow risk in Utils.c.
- Copyright year 2026 in all new files.
