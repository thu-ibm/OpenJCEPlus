# Test Tag Integration: AES OpenSSL classes added to suite runners
**Date:** 2026-07-27

## What was done

Added `@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)` to all 10 AES test classes in `openjceplus/`:
- TestAES256Interop, TestAESKeyWrap, TestAESGCMUpdate, TestAESGCMWithKeyAndIvCheck
- TestAESGCMUpdateInteropBC, TestAESGCMBufferIV, TestAESGCM_ExtIV, TestAESGCM_IntIV
- TestAESCCMParameters, TestAESCCMInteropBC

Updated `TestOpenJCEPlus.java` to scan both packages:
```java
@SelectPackages({"ibm.jceplus.junit.tests", "ibm.jceplus.junit.openjceplus"})
```

## Why

`TestOpenJCEPlus` suite (and CI tag expressions) previously only scanned `ibm.jceplus.junit.tests`
and filtered by `@IncludeTags`. Our AES classes were in `openjceplus/` with no tags — invisible to suite runners.

## Result

- 10/10 AES tests still PASS
- Committed as `ef4c2cf`
