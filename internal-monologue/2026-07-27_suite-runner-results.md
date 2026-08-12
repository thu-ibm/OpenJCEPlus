# Suite Runner: TestOpenJCEPlus with OpenSSL tag
**Date:** 2026-07-27

## Command
`cmd /c run_suite_openssl.bat` (runs TestOpenJCEPlus suite with `-Dgroups=OpenJCEPlus_OpenSSL`)

## Our AES tests — all PASS via suite runner
All 10 AES classes were discovered and passed:
- TestAES256Interop (18), TestAESCCMInteropBC (2), TestAESCCMParameters (3)
- TestAESGCM_ExtIV (28), TestAESGCM_IntIV (8), TestAESGCMBufferIV (1)
- TestAESGCMUpdate (20), TestAESGCMUpdateInteropBC (3), TestAESGCMWithKeyAndIvCheck (1)
- TestAESKeyWrap (64)

## Pre-existing failures in tests/ package (NOT our issue)
SHA/AES parameterized test classes (TestSHA*.java, TestAESGCM etc. in tests/ package) fail with:
`ParameterResolutionException: No ParameterResolver registered for parameter [Set<String> arg0]`
in `TestArguments.getEnabledProviders()`.

This is a pre-existing problem — those classes use `@ParameterizedClass` + `@MethodSource` with
`ProviderListParameterResolver`, which isn't injected when run via `@Suite`. Not related to our changes.
