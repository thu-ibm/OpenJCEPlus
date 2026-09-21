# Clarify build and suite commands

- Confirmed that the OpenSSL DLL was built and copied using `buildNativeOpenSSL_Win64_AutoEnv.bat`, not `buildNativeWin64_AutoEnv.bat`.
- Confirmed that the full-suite attempt used `run_suite_openssl.bat` directly.
- The suite script currently points `OCK_PATH` to a directory that does not exist, causing the post-change suite run's seven EdDSA/OCK loading errors.
