# Cherry-pick PR 1492 commits not in thu/openssl-aes

## What was done
Pulled latest commits from `ibm/pr-1492` (IBM/OpenJCEPlus#1492) that were not yet in `thu/openssl-aes`.

## Analysis
- Merge base between our branch and `ibm/pr-1492`: `e1ff2dee`
- PR 1492 tip: `061edac5` (Support OpenSSL backend and implement message digest)
- New commits in PR 1492 not in our history by SHA:
  - `b0c1c0b4` Add generic ML-DSA KeyFactory and Signature (#1667)
  - `e0e1440e` Use SystemAccessUtils.fileExists in loadIfExists (#1758)
  - `51fcc978` Add PBKDF2 FIPS restrictions to README (#1759)
  - `02cb077d` Remove static from test variable (#1723)
  - `061edac5` Support OpenSSL backend and implement message digest (PR-specific)

Note: `1adc30e1`, `2b187ec5`, `b85643e8` were already cherry-picked in prior sessions (different SHA, same content).

## Actions taken
1. Stashed working tree changes
2. Cherry-picked `b0c1c0b4`, `e0e1440e`, `51fcc978`, `02cb077d` — one conflict in `NativeOCKImplementation.java` (add/add for `loadIfExists` method) resolved by accepting incoming version
3. Cherry-picked `061edac5` — multiple add/add conflicts where our branch already has more advanced versions; resolved all with `--ours` then `--skip` (commit empty after keeping ours)
4. Popped stash

## Result
4 new commits added to branch:
- `ed3382b9` Add generic ML-DSA KeyFactory and Signature (#1667)
- `fef8d046` Use SystemAccessUtils.fileExists in loadIfExists (#1758)
- `78c853e9` Add PBKDF2 FIPS restrictions to README (#1759)
- `2955e9d2` Remove static from test variable (#1723)
