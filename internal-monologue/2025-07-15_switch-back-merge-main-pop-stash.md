# 2025-07-15 Switch back to thu/openssl-aes, merge main, pop stash

## Actions
1. `git checkout thu/openssl-aes`
2. `git merge main` (rebase aborted due to heavy conflict density; merge used instead)
3. Resolved conflicts:
   - `Digest.java`: kept SystemAccessUtils + HashMap/Map imports
   - `NativeOCKImplementation.java`: kept SystemAccessUtils import + loadIfExists() from main
   - `GCMCipher.java`: removed duplicate imports from conflict, kept clean set
   - `PQCKeyFactory.java`: accepted main's dash style (-) over em-dash
   - `ExtendedRandom.java`: accepted main's thread-local PRNG context refactor
   - Deleted openjceplus/TestAESCCMInteropBC.java + TestAESGCMUpdateInteropBC.java (moved to tests/ in main)
4. `git stash pop` - all 29 stashed changes restored cleanly

## Result
Branch thu/openssl-aes is now 15 commits ahead of origin, merged with main, stash restored.
