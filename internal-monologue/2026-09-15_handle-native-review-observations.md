# Handle native review observations

- Added balanced function-entry/function-exit logging to `SIGNATURE_update` in `OpenSSLSignature.c`.
- Replaced the inline `GCM_update` output bounds/overflow check with the shared `validateOutputBuffer()` helper in `OpenSSLGCM.c`.
- Documented the required pre-OpenSSL-4 EVP migrations in `OpenSSLDSAKey.c` and `OpenSSLECKey.c`; did not attempt the broad behavioral migration in this cleanup. `OpenSSLRSAKey.c` already documents why its low-level API use is intentional.
- Rebuilt the Windows OpenSSL DLL successfully with `buildNativeOpenSSL_Win64_AutoEnv.bat`.
- Targeted OpenSSL-tagged GCM, DSA, and ECDSA validation passed: 77 tests, 0 failures, 0 errors, 0 skipped.
- A full suite attempt ran 1147 tests but had 7 unrelated EdDSA errors because the configured OCK dependency could not load. The prior known-good suite remains 1147 tests, 0 failures, 0 errors, 36 skipped.
- `git diff --check` passed.
