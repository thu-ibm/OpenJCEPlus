@echo off
REM ============================================================================
REM Compile OpenJCEPlus Java sources (OpenSSL backend, no native rebuild)
REM ============================================================================
setlocal

set OPENSSL_HOME=C:\OpenSSL-v3
set OPENSSL_CONF=%OPENSSL_HOME%\ssl\openssl.cnf
set JGSKIT_PATH=C:\Users\Administrator\openjdk_dev\OCK
set OCK_PATH=C:\Users\Administrator\openjdk_dev\OCK
set PATH=%OPENSSL_HOME%\bin;%JGSKIT_PATH%;%OCK_PATH%;%PATH%

echo Compiling OpenJCEPlus (skip native, OpenSSL paths set)...
echo.

mvn compile ^
    -Dock.library.path=%OCK_PATH% ^
    -Djgskit.library.path=%JGSKIT_PATH% ^
    -Dskip.native.compile=true

endlocal
