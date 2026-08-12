# AES Tests: 10/10 PASS after encoding fixes
**Date:** 2026-07-27

## Issues encountered and fixed

### 1. Digest.java — UTF-16 LE BOM
- File was written with PowerShell UTF-16 LE in a prior session
- Caused `unmappable character (0xFF/0xFE)` + hundreds of `illegal character: '\u0000'` errors
- Fix: re-written from `git show HEAD:...` via `[System.IO.File]::WriteAllText(... UTF8Encoding($false))`

### 2. NativeOCKImplementation.java — stale `extends NativeImplementation`
- Commit `f6d5575` left the old version with `import/extends NativeImplementation`
- `NativeImplementation.java` does not exist in this branch → compile error
- Fix: restored from `origin/main` (the correct version with no `NativeImplementation` reference)

### 3. buildNativeWin64.bat — UTF-16 LE BOM
- Same encoding issue; Maven exec-maven-plugin ran it during compile phase → garbled command → exit 1
- Fix: re-written from `origin/main` via same UTF-8 method

### 4. run_all_aes_tests.bat — missing `-Dskip.native.compile=true`
- Maven `compile` phase invoked `buildNativeWin64.bat` which requires `GSKIT_HOME` (OCK) — not available
- Fix: added `-Dskip.native.compile=true` to every `mvn` invocation in the test script

## Result
All 10 test classes, 148 test methods: **PASS**

## Committed as
`6355362 Fix UTF-16 LE encoding in Digest.java and buildNativeWin64.bat, revert NativeOCKImplementation, add -Dskip.native.compile to test script`
