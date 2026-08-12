# PR File Scope Analysis — openssl-aes branch
**Date:** 2026-07-27

## Summary
Files changed vs base (9d53388) = all files in `git diff --name-only 9d53388 HEAD`.
Categorised by whether they should be in the PR or excluded.

## DO NOT COMMIT (should be excluded / gitignored)
- `.idea/` — IDE project files
- `internal-monologue/` — session notes
- `run_suite_openssl.bat` — ad-hoc local test runner
- `src/main/native/libjgskit_openssl_64.dll` — pre-built binary (build artifact)
- `run_all_aes_tests.bat` — local convenience script (committed in f6d5575, should be dropped)

## Already committed — in scope for PR
See full list in the artifact.
