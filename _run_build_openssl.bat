@echo off
set JAVA_HOME=C:\Users\Administrator\Downloads\opensdk\semeru\jdk
set OPENSSL_HOME=C:\OpenSSL-v3
call "C:\MSVS2\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
call buildNativeWin64OpenSSL.bat

:: Copy DLL to JVM bin directory
echo Copying DLL to JVM bin directory...
copy src\main\native\openssl\libjgskit_openssl_64.dll "%JAVA_HOME%\bin\" >nul
if errorlevel 1 (
    echo WARNING: Failed to copy DLL to JVM bin directory
) else (
    echo DLL copied successfully to: %JAVA_HOME%\bin\
)
