@echo off
setlocal

set OPENSSL_HOME=C:\OpenSSL-v3
set OPENSSL_CONF=%OPENSSL_HOME%\ssl\openssl.cnf
set JGSKIT_PATH=C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin
set OCK_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK
set PATH=%OPENSSL_HOME%\bin;%JGSKIT_PATH%;%OCK_PATH%;%PATH%

echo Running TestRSA#testRSAPlainCipher (OpenSSL tag only)...
echo.

mvn -Dtest="ibm.jceplus.junit.tests.TestRSA#testRSAPlainCipher" ^
    -Dgroups=OpenJCEPlus_OpenSSL ^
    -Djgskit.library.path=%JGSKIT_PATH% ^
    -Dock.library.path=%OCK_PATH% ^
    -Dopenjceplus.useOpenSSL=true ^
    -Dskip.native.compile=true ^
    -Dsurefire.failIfNoSpecifiedTests=false ^
    -DfailIfNoTests=false ^
    test

endlocal
