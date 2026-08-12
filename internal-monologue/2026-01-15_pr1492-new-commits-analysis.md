# PR1492 New Commits Analysis
**Date:** 2026-01-15

Since original review, 3 new commits were added to IBM/OpenJCEPlus PR#1492:
- `a7709bf8` 2026-07-21 Update github actions
- `e5d018c7` 2026-07-21 Add to windows path  
- `76d997e1` 2026-07-21 Change cflags to link statically
- `86a3a25d` 2026-07-24 Add openssl field
- `3fc08f5f` 2026-07-13 Update test tags and method sources

## Changes to carry into thu_main (openssl_aes branch)

### GROUP 1 — Test infrastructure refactor (commit 3fc08f5) — ALL NEW, must include
The biggest addition. A full test tag/parameter resolver refactor to support OpenSSL and OCK as distinct test targets.

**New files (5):**
- `src/test/java/.../tests/parameters/resolvers/KeySizeListParameterResolver.java`
- `src/test/java/.../tests/parameters/resolvers/AESKeySizeListParameterResolver.java`
- `src/test/java/.../tests/parameters/resolvers/RSAKeySizeListParameterResolver.java`
- `src/test/java/.../tests/parameters/resolvers/RSAMultithreadKeySizeListParameterResolver.java`
- `src/test/java/.../tests/parameters/resolvers/ProviderListParameterResolver.java`
- `src/test/OpenSSLOnly.config` — sets NativeProvider=OPENSSL for all digest services

**Modified files (major changes):**
- `Tags.java` — adds OPENJCEPLUS_OPENSSL, OPENJCEPLUS_OCK tags; renames MULTITHREAD
- `TestProvider.java` — adds OpenJCEPlus_OpenSSL and OpenJCEPlus_OCK enum entries with configFile
- `TestArguments.java` — refactored to accept Set<String> providers + List<Integer> keySizes via resolvers
- `BaseTestMultiThread.java` — getTagName() → getTagExpression()
- `TestAll.java` — adds IncludeTags for OpenSSL/OCK, ExcludeClassNamePatterns for multithread
- `TestOpenJCEPlus.java` — IncludeTags now includes OpenSSL and OCK tags
- `TestMultiThreadOpenJCEPlus.java` — uses tag expression with | operator
- `TestMultiThreadOpenJCEPlusFIPS.java` — uses tag expression
- `BaseTestRSA.java` — typo fix: "SHA-11" → "SHA-1"
- `TestAES.java` — uses AESKeySizeListParameterResolver + @ExtendWith
- `TestAESGCM.java` — same
- `TestRSA.java` — uses RSAKeySizeListParameterResolver
- `TestProviderServices.java` — copyright + MULTITHREAD tag rename
- All SHA/HMAC/ChaCha20/DES/DSA/EC test files — tag renames only (1-2 line changes each)
- `TestArguments.java` — major refactor to provider-set-based API
- `TestProvider.java` — adds configFile field, OpenSSL/OCK entries
- `TestMD5.java` — now tagged OPENJCEPLUS_OPENSSL_NAME only

### GROUP 2 — Digest.java multi-backend context cache (in original PR, confirmed present)
- Multi-backend HashMap-based context cache replacing static arrays — ALREADY INCLUDED from PR1492 original

### GROUP 3 — CI/build additions
- `utils.groovy` — getOpenSSL() function, OPENSSL_HOME in runOpenJCEPlus, PATH addition for MSVC
- `.github/workflows/github-actions.yml` — OpenSSL headers install, OPENSSL_HOME env var

### GROUP 4 — Config files
- `src/test/OCKOnly.config` — ALREADY applied
- `src/test/OpenSSLOnly.config` — NEW, must add (OpenSSL-only digest config)
