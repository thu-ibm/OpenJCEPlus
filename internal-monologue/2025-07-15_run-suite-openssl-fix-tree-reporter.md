# 2025-07-15 Run run_suite_openssl.bat - fix tree reporter version

## Problem
Suite crashed with `PluginContainerException`: `AnsiMessageBuilder` missing —
caused by `maven-surefire-junit5-tree-reporter:1.5.1` being incompatible with
`maven-surefire-plugin:3.5.3`.

## Fix
In `pom.xml` (2 occurrences), downgraded:
  `maven-surefire-junit5-tree-reporter` 1.5.1 → 1.3.0

## Result
Tests run: 1147, Failures: 0, Errors: 0, Skipped: 36 — BUILD SUCCESS
