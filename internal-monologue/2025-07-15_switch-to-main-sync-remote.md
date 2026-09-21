# 2025-07-15 Switch to main branch and sync from remote

## Actions
1. `git stash` — saved working changes on `thu/openssl-aes`
2. `git checkout main` — branch "master" did not exist; default branch is `main`
3. `git pull origin main` — fast-forwarded 9d533884..b17f8f57

## Notable changes pulled
- New: PBMAC1Core.java, SystemAccessUtils.java, PBMAC1 tests
- New: PQC key/signature improvements
- Refactored: TestAESCCMInteropBC, TestAESGCMUpdateInteropBC moved to tests/
- New test parameter resolvers
- 112 files changed, 3801 insertions, 897 deletions
