# How to Sync `thu/openssl-aes` with Remote `main`

This document records the process used to bring the `thu/openssl-aes` feature branch
up to date with the upstream `main` branch, including how conflicts were resolved.
Follow these steps each time `main` has new commits you want to incorporate.

---

## Prerequisites

- You are working on the `thu/openssl-aes` branch.
- You have uncommitted working-directory changes you want to keep.

---

## Step 1 — Stash Working-Directory Changes

If you have unstaged/uncommitted changes:

```bash
git stash
```

This saves your working-directory changes so they are not lost during the merge.

---

## Step 2 — Switch to `main` and Pull Latest

```bash
git checkout main
git pull origin main
```

This fast-forwards your local `main` to match `origin/main`.

---

## Step 3 — Switch Back to `thu/openssl-aes`

```bash
git checkout thu/openssl-aes
```

---

## Step 4 — Merge `main` into the Feature Branch

```bash
git merge main --no-edit
```

> **Why merge and not rebase?**
> This branch has many commits that overlap heavily with upstream `main`
> (both branches touched the same files). Rebase replays every commit one by
> one, causing repeated conflicts at each step. A single merge commit resolves
> everything in one pass.

---

## Step 5 — Resolve Merge Conflicts

After running `git merge main` you may see conflicts. The sections below list
the files that conflicted during the July 2025 sync and how they were resolved.
Use these as a guide for future syncs — the same files are likely to conflict
again because both branches actively modify them.

### 5a. `src/main/java/com/ibm/crypto/plus/provider/base/Digest.java`

**Nature:** Both sides added imports.

- HEAD (`main`) added: `import com.ibm.crypto.plus.provider.SystemAccessUtils;`
- Our branch added: `import java.util.HashMap;` and `import java.util.Map;`

**Resolution:** Keep **both** import groups:

```java
import com.ibm.crypto.plus.provider.SystemAccessUtils;
import java.util.HashMap;
import java.util.Map;
```

### 5b. `src/main/java/com/ibm/crypto/plus/provider/ock/NativeOCKImplementation.java`

**Nature:** Both sides added an import; HEAD also added a method.

- HEAD added: `import com.ibm.crypto.plus.provider.SystemAccessUtils;` and the
  `loadIfExists(File)` helper method.
- Our branch added: `import com.ibm.crypto.plus.provider.base.NativeImplementation;`
  (already present from earlier commits; not needed here).

**Resolution:** Keep HEAD's import (`SystemAccessUtils`) and keep HEAD's
`loadIfExists()` method. Discard our branch's section (it was empty or
already applied by a prior commit).

### 5c. `src/main/java/com/ibm/crypto/plus/provider/base/GCMCipher.java`

**Nature:** HEAD added several imports; our branch's section was empty.

- HEAD added: `SystemAccessUtils`, `ByteBuffer`, `Arrays`, `HashMap`, `Map`,
  and four `javax.crypto.*` imports.
- Our branch: empty (the commit being replayed had not yet added them).

**Resolution:** Keep HEAD's imports. Remove the conflict markers. On a
subsequent commit in the rebase/replay the same file may conflict again —
if our commit removes `SystemAccessUtils` (because it was moved to the
adapter layer), accept the removal and keep the remaining imports without
duplicating them.

### 5d. `src/test/java/ibm/jceplus/junit/openjceplus/TestAESCCMInteropBC.java`  
### `src/test/java/ibm/jceplus/junit/openjceplus/TestAESGCMUpdateInteropBC.java`

**Nature:** `modify/delete` — `main` deleted these files (they were moved to
`src/test/java/ibm/jceplus/junit/tests/`); our branch had modified them.

**Resolution:** Accept the deletion. The new canonical copies live in `tests/`.

```bash
git rm src/test/java/ibm/jceplus/junit/openjceplus/TestAESCCMInteropBC.java
git rm src/test/java/ibm/jceplus/junit/openjceplus/TestAESGCMUpdateInteropBC.java
```

### 5e. `src/main/java/com/ibm/crypto/plus/provider/PQCKeyFactory.java`

**Nature:** Cosmetic — our branch used Unicode em-dashes (`—`) in comments;
`main` uses plain ASCII hyphens (`-`).

**Resolution:** Accept `main`'s version (ASCII hyphens).

### 5f. `src/main/java/com/ibm/crypto/plus/provider/base/ExtendedRandom.java`

**Nature:** Structural refactor in `main` — replaced a simple `prngContextId`
field with a thread-local PRNG context pool (`PRNGContextPointer`,
`prngContextBufferSha256`, `prngContextBufferSha512`).

**Resolution:** Accept `main`'s version entirely. The thread-local design is
the upstream canonical implementation.

---

## Step 6 — Stage Resolved Files and Complete the Merge

```bash
git add <resolved-files>
git merge --continue
```

Git will open an editor for the merge commit message. Save and close to
complete the merge (or use `--no-edit` when running `git merge` in Step 4).

---

## Step 7 — Pop the Stash

```bash
git stash pop
```

This re-applies your working-directory changes on top of the merged branch.
If there are stash conflicts, resolve them as you would any merge conflict.

---

## Step 8 — Verify

Run the test suite to confirm nothing is broken after the merge:

```bash
.\run_suite_openssl.bat
```

Expected: `Tests run: ≥1147, Failures: 0, Errors: 0`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `fatal: --continue expects no arguments` | Passed args to `git merge --continue` | Run `git merge --continue` with no arguments |
| Rebase with many repeated conflicts | Too many overlapping commits | Abort with `git rebase --abort` and use `git merge main` instead |
| `maven-surefire` crash: `AnsiMessageBuilder` missing | `maven-surefire-junit5-tree-reporter` version incompatible with surefire 3.5.x | Downgrade to `1.3.0` in both `<plugin>` blocks in `pom.xml` |
| DLL build fails on `OpenSSLDSAKey.c` with `C2018`/`C2143` | Unicode characters (`—`, smart quotes, `@`) in C comments | Replace em-dashes with `-`, remove `@param`/`@return` tags, fix any `*/` inside a block comment |
