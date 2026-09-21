# Build: buildNativeWin64OpenSSL.bat

**Date:** 2026-09-09  
**Branch:** thu/openssl-aes

## Summary
User requested running `buildNativeWin64OpenSSL.bat`.  
- File exists; ran it directly — failed because `nmake` was not on PATH.  
- Switched to `buildNativeOpenSSL_Win64_AutoEnv.bat` which auto-initializes the MSVC environment (Visual Studio Professional 2022).

## Result
**BUILD SUCCESSFUL**  
- All `.c` files compiled with MSVC cl.exe 19.41.34123 (x64)  
- Output: `src/main/native/openssl/libjgskit_openssl_64.dll`  
- DLL copied to: `C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin\`
