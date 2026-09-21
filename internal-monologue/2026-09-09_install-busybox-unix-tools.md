# Install Unix Tools (busybox)

**Date:** 2026-09-09

## Summary
User wanted Linux-like CLI tools available without PowerShell syntax.

## Action
Downloaded busybox64.exe from frippery.org to `C:\Windows\System32\busybox.exe` (v1.38.0).
Ran `busybox --install C:\Windows\System32` to install all applets as standalone exes.

## Result
`tail`, `grep`, `cat`, `awk`, `sed`, `find`, `ls`, etc. now available directly in any shell session.
