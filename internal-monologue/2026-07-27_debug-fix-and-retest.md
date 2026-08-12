# Debug Fix and Retest
**Date:** 2026-07-27

## Change
`NativeOpenSSLAdapter.java` — enabled `sun.security.util.Debug` to match `NativeOCKAdapter`:
- Added `import sun.security.util.Debug`
- Replaced disabled comment with `private static Debug debug = Debug.getInstance("jceplus")`
- Enabled `if (debug != null) { exceptionToThrow.printStackTrace(System.out); }` in error path
- Cleaned stale comment from `setOpenSSLExceptionCause()`

Committed as `e7b398d`.

## Results
- DLL rebuilt: BUILD SUCCESSFUL (9 objects)
- All 10 AES tests: PASS (148 methods)
