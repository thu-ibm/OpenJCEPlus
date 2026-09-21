@echo off
setlocal

set OPENSSL_HOME=C:\OpenSSL-v3
set OPENSSL_CONF=%OPENSSL_HOME%\ssl\openssl.cnf
set JGSKIT_PATH=C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin
set OCK_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK
set PATH=%OPENSSL_HOME%\bin;%JGSKIT_PATH%;%OCK_PATH%;%PATH%

echo Running ibm.jceplus.junit.tests package (OpenJCEPlus OCK tag)...
echo.

mvn -Djgskit.library.path=%JGSKIT_PATH% ^
    -Dock.library.path=%OCK_PATH% ^
    -Dskip.native.compile=true ^
    -Dsurefire.useFile=false ^
    -Dtest=ibm.jceplus.junit.suites.TestOpenJCEPlus ^
    -Dgroups=OpenJCEPlus ^
    -DexcludedGroups=Multithread ^
    test

endlocal
