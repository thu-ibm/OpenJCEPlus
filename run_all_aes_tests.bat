@echo off
REM ============================================================================
REM OpenJCEPlus OpenSSL Backend AES Test Suite
REM ============================================================================

setlocal enabledelayedexpansion

echo ========================================
echo OpenJCEPlus OpenSSL Backend Test Suite
echo ========================================
echo.

REM Set environment variables
set OPENSSL_HOME=C:\OpenSSL-v3
set OPENSSL_CONF=%OPENSSL_HOME%\ssl\openssl.cnf
set PATH=%OPENSSL_HOME%\bin;%PATH%

REM Library paths - DLL is in JDK bin directory
set JGSKIT_PATH=C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin
set OCK_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK
set PATH=%JGSKIT_PATH%;%OCK_PATH%;%PATH%

echo Environment Configuration:
echo - OPENSSL_HOME: %OPENSSL_HOME%
echo - OPENSSL_CONF: %OPENSSL_CONF%
echo - Library paths configured
echo.

REM Configuration file
set CONFIG_FILE=./src/test/ProviderOpenSSLAttrs.config

echo Using OpenSSL configuration: %CONFIG_FILE%
echo.

REM Test results tracking
set TOTAL_TESTS=0
set PASSED_TESTS=0
set FAILED_TESTS=0

REM ============================================================================
REM Run All GCM Tests
REM ============================================================================

REM Array of test names - All AES-related tests (non-FIPS)
set TESTS=TestAES256Interop TestAESKeyWrap TestAESGCMUpdate TestAESGCMWithKeyAndIvCheck TestAESGCMUpdateInteropBC TestAESGCMBufferIV TestAESGCM_ExtIV TestAESGCM_IntIV TestAESCCMParameters TestAESCCMInteropBC

for %%T in (%TESTS%) do (
    set /a TOTAL_TESTS+=1
    
    echo.
    echo [!TOTAL_TESTS!] Running: %%T
    echo ============================================================================
    echo.
    
    call mvn -Dtest=ibm.jceplus.junit.openjceplus.%%T ^
        -Dopenjceplus.useOpenSSL=true ^
        -Djgskit.library.path=%JGSKIT_PATH% ^
        -Dock.library.path=%OCK_PATH% ^
        -Dskip.native.compile=true ^
        test
    
    if !ERRORLEVEL! EQU 0 (
        echo.
        echo [PASS] %%T
        set /a PASSED_TESTS+=1
    ) else (
        echo.
        echo [FAIL] %%T
        set /a FAILED_TESTS+=1
    )
)

REM ============================================================================
REM Test Summary
REM ============================================================================

echo.
echo ============================================================================
echo Test Summary
echo ============================================================================
echo Total Tests Run:     %TOTAL_TESTS%
echo Passed:              %PASSED_TESTS%
echo Failed:              %FAILED_TESTS%
echo ============================================================================

echo.

if %FAILED_TESTS% GTR 0 (
    echo RESULT: SOME TESTS FAILED
    exit /b 1
) else (
    echo RESULT: ALL TESTS PASSED
    echo.
    exit /b 0
)


