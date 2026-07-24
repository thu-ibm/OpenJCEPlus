###############################################################################
#
# Copyright IBM Corp. 2025
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR = $(MAKEDIR)\..\..\..

PLAT = win
CFLAGS= -nologo -DWINDOWS -MD

#DEBUG_DETAIL = -DDEBUG_OPENSSL_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_CIPHER_DETAIL
#DEBUG_DATA = -DDEBUG_OPENSSL_DATA -DDEBUG_DIGEST_DATA -DDEBUG_CIPHER_DATA
#DEBUG_FLAGS = -DDEBUG $(DEBUG_DETAIL) $(DEBUG_DATA)

BUILDTOP = $(TOPDIR)\target\buildopenssl$(PLAT)
HOSTOUT = $(BUILDTOP)\host64
JAVACLASSDIR = $(TOPDIR)\target\classes

OBJS= \
	OpenSSLNativeInterface.obj \
	OpenSSLSymmetricCipher.obj \
	OpenSSLGCM.obj \
	OpenSSLCCM.obj \
	OpenSSLKeyWrap.obj \
	OpenSSLDigest.obj \
	OpenSSLSignature.obj \
	OpenSSLKeyPairGenerator.obj \
	OpenSSLHMAC.obj \
	OpenSSLPBKDF2.obj \
	OpenSSLHKDF.obj \
	OpenSSLRandom.obj \
	OpenSSLUtils.obj \
	OpenSSLHelpers.obj \
	BuildDate.obj

TARGET = libjgskit_openssl_64.dll

JGSKIT_RC_SRC = openssl\jgskit_resource.rc
JGSKIT_RC_OBJ = jgskit_resource.res

all : copy cleanup

copy : $(TARGET)
	-@if not exist $(HOSTOUT) mkdir $(HOSTOUT)
	-@copy *.obj $(HOSTOUT)
	-@copy jgskit_resource.res $(HOSTOUT)
	-@copy libjgskit_openssl_64.dll $(HOSTOUT)

cleanup :
	@echo Cleaning up build artifacts from source directory...
	-@if exist *.obj del *.obj
	-@if exist *.exp del *.exp
	-@if exist *.lib del *.lib
	-@if exist *.res del *.res
	@echo Build artifacts cleaned up

$(TARGET) : $(OBJS) $(JGSKIT_RC_OBJ)
	link -dll -out:$@ $(OBJS) $(JGSKIT_RC_OBJ) -LIBPATH:"$(OPENSSL_HOME)\lib" libcrypto.lib libssl.lib ws2_32.lib crypt32.lib advapi32.lib user32.lib

$(JGSKIT_RC_OBJ) : $(JGSKIT_RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(JGSKIT_RC_SRC)

OpenSSLNativeInterface.obj : openssl\OpenSSLJNI.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -Iopenssl openssl\OpenSSLJNI.c -Fo$@

OpenSSLSymmetricCipher.obj : openssl\OpenSSLSymmetricCipher.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -Iopenssl openssl\OpenSSLSymmetricCipher.c

OpenSSLGCM.obj : openssl\OpenSSLGCM.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLGCM.c
		
OpenSSLCCM.obj : openssl\OpenSSLCCM.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLCCM.c

OpenSSLKeyWrap.obj : openssl\OpenSSLKeyWrap.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLKeyWrap.c
                		
OpenSSLDigest.obj : openssl\OpenSSLDigest.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLDigest.c

OpenSSLSignature.obj : openssl\OpenSSLSignature.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLSignature.c

OpenSSLKeyPairGenerator.obj : openssl\OpenSSLKeyPairGenerator.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLKeyPairGenerator.c

OpenSSLHMAC.obj : openssl\OpenSSLHMAC.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLHMAC.c

OpenSSLPBKDF2.obj : openssl\OpenSSLPBKDF2.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLPBKDF2.c

OpenSSLHKDF.obj : openssl\OpenSSLHKDF.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLHKDF.c

OpenSSLRandom.obj : openssl\OpenSSLRandom.c openssl\OpenSSLExceptionCodes.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -I..\include -Iopenssl openssl\OpenSSLRandom.c

OpenSSLUtils.obj : openssl\OpenSSLUtils.c
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -Iopenssl openssl\OpenSSLUtils.c

OpenSSLHelpers.obj : openssl\OpenSSLHelpers.c openssl\OpenSSLHelpers.h
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -Iopenssl openssl\OpenSSLHelpers.c

BuildDate.obj : openssl\BuildDate.c FORCE
	cl $(DEBUG_FLAGS) $(CFLAGS) -c -I"$(OPENSSL_HOME)\include" -I"$(JAVA_HOME)\include" -I"$(JAVA_HOME)\include\win32" -Iopenssl openssl\BuildDate.c

FORCE :

# Headers should be generated via Maven build, not here
# $(OBJS) : headers

# headers :
# 	@echo Compiling OpenJCEPlus OpenSSL headers
# 	$(JAVA_HOME)\bin\javac \
# 		--add-exports java.base/sun.security.util=openjceplus \
# 		--add-exports java.base/sun.security.util=ALL-UNNAMED \
# 		-d $(JAVACLASSDIR) \
# 		-h $(TOPDIR)\src\main\native\openssl\ \
# 		$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\base\*.java \
# 		$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\openssl\*.java

clean :
	@echo Cleaning all build artifacts...
	-@if exist $(HOSTOUT)\*.obj del $(HOSTOUT)\*.obj
	-@if exist $(HOSTOUT)\*.exp del $(HOSTOUT)\*.exp
	-@if exist $(HOSTOUT)\*.lib del $(HOSTOUT)\*.lib
	-@if exist $(HOSTOUT)\*.dll del $(HOSTOUT)\*.dll
	-@if exist $(HOSTOUT)\*.res del $(HOSTOUT)\*.res
	-@if exist *.obj del *.obj
	-@if exist *.exp del *.exp
	-@if exist *.lib del *.lib
	-@if exist *.dll del *.dll
	-@if exist *.res del *.res
	@echo All build artifacts cleaned

.PHONY : all clean copy cleanup
