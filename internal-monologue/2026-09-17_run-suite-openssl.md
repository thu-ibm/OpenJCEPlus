# 2026-09-17 — Run run_suite_openssl.bat

## Action
Executed `run_suite_openssl.bat` via PowerShell, teeing output to `suite_out_latest.txt`.

## Result
- **BUILD SUCCESS** in 7 min 47 sec
- Tests run: **1147**, Failures: **0**, Errors: **0**, Skipped: **36**
- The 36 skipped tests are FIPS-only assertions (testFIPSBadRSAKeySizes, testDisallowSHA1inFIPS_*, etc.) — expected skips in non-FIPS OpenSSL mode.
- `ForkStarter IOException: No value present` warnings are benign surefire diagnostics, not test failures.
