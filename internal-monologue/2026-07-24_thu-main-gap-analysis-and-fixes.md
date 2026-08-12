# thu_main Gap Analysis and Fixes
**Date:** 2026-07-24

## Gap analysis findings

After initial branch creation, gap analysis found 7 missing items not carried over:

1. **pom.xml** — missing `build.target.ojplib.dir` per-platform (8 profiles), `--add-exports/opens` for resolvers package, `openjceplus.library.path` surefire system property
2. **buildNative.sh / buildNativeMac.sh / buildNativeWin64.bat** — missing OPENSSL_HOME check + openssl native build invocation (Linux/Mac CI would fail without this)
3. **common.*.mak (4 files)** — missing `-I${NATIVE_LIB_HOME}/include` for OpenSSL headers on Linux/Mac builds
4. **github-actions.yml** — missing apt-get libssl-dev, OpenSSL header copy, OPENSSL_HOME/OPENSSL_LIB_LOCATION env vars, openssl.library.path Maven property
5. **utils.groovy** — missing getOpenSSL() function and OPENSSL_HOME in runOpenJCEPlus
6. **Digest.java** — ibm/main had reverted to single-backend static arrays; restored PR1492's HashMap-per-backend for multi-backend correctness
7. **.gitignore** — missing generated JNI header patterns for openssl package

## Fixes applied

- Copied buildNative*.sh/bat, utils.groovy, github-actions.yml, common.*.mak, Digest.java directly from PR1492 HEAD
- Applied pom.xml changes surgically via PowerShell string replacement
- Appended .gitignore patterns

## Result

All 7 items applied, committed as `1e502de`.
AES tests re-run: **10/10 PASSED**, zero regressions.

## Final branch state
```
1e502de  PR1492 build/CI/multi-backend additions (gap fixes)
f6d5575  ojp_master: working AES OpenSSL implementation
80085e1  Kostas: add openssl field
80f94db  Kostas: change cflags to link statically
ba00f78  Kostas: add to windows path
10df7d7  Kostas: update github actions
93a4657  Kostas: create OpenSSL java classes
b756660  Kostas: update test tags and method sources
9d53388  thu-ibm/main HEAD (base)
```

## Nothing remaining
Branch is complete. Ready to push to thu-ibm fork when instructed.
