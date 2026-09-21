::#############################################################################
::#
::# Copyright IBM Corp. 2026
::#
::# This code is free software; you can redistribute it and/or modify it
::# under the terms provided by IBM in the LICENSE file that accompanied
::# this code, including the "Classpath" Exception described therein.
::#############################################################################

@echo off
setlocal enabledelayedexpansion

set JAVA_HOME=C:\Users\Administrator\Downloads\opensdk\semeru\jdk
set OPENSSL_HOME=C:\OpenSSL-v3

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" (
	echo "ERROR: vswhere.exe not found, cannot detect Visual Studio"
	goto :eof
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
	set "VS_PATH=%%i"
)

if not defined VS_PATH (
	echo "ERROR: Could not detect Visual Studio installation"
	goto :eof
)

call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"

call buildNativeWin64.bat

if exist "src\main\native\openssl\libjgskit_openssl_64.dll" (
	echo Copying libjgskit_openssl_64.dll to %JAVA_HOME%\bin\...
	copy src\main\native\openssl\libjgskit_openssl_64.dll "%JAVA_HOME%\bin\" >nul
	if errorlevel 1 (
		echo WARNING: Failed to copy libjgskit_openssl_64.dll to %JAVA_HOME%\bin\
	) else (
		echo Copied successfully.
	)
)

@endlocal
