@echo off
setlocal

echo Cleaning up build artifacts and diagnostic files...

:: Native object files and build intermediates
del /S /Q src\main\native\openssl\*.obj 2>nul
del /S /Q src\main\native\ock\*.obj 2>nul
del /S /Q src\main\native\common\*.obj 2>nul
del /S /Q src\main\native\openssl\*.res 2>nul
del /S /Q src\main\native\openssl\*.lib 2>nul
del /S /Q src\main\native\openssl\*.exp 2>nul
del /S /Q src\main\native\openssl\*.dll 2>nul

:: Crash dumps, javacores, and traces
del /Q core.*.dmp 2>nul
del /Q javacore.*.txt 2>nul
del /Q jitdump.*.dmp 2>nul
del /Q Snap.*.trc 2>nul

:: Temporary test and output logs
del /Q suite_out*.txt 2>nul
del /Q suite_baseline.txt 2>nul
del /Q build_openssl.txt 2>nul
del /Q .bob_tmp_* 2>nul
del /Q tmpPQCKS.pkcs12 2>nul

echo Cleanup completed.
