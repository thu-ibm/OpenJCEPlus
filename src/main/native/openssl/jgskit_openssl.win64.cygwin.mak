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
	OpenSSLHMAC.obj \
	OpenSSLPBKDF2.obj \
	OpenSSLHKDF.obj \
	OpenSSLUtils.obj \
	OpenSSLHelpers.obj \
	BuildDate.obj

TARGET = libjgskit_openssl_64.dll

JGSKIT_RC_SRC = jgskit_resource.rc
JGSKIT_RC_OBJ = jgskit_resource.res

all : copy

copy : $(TARGET)
	-@if not exist $(HOSTOUT) mkdir $(HOSTOUT)
	-@copy *.obj $(HOSTOUT)
	-@copy jgskit_resource.res $(HOSTOUT)
	-@copy libjgskit_openssl_64.dll $(HOSTOUT)

$(TARGET) : $(OBJS) $(JGSKIT_RC_OBJ)
	link -dll -out:$@ $(OBJS) $(JGSKIT_RC_OBJ) -LIBPATH:"$(OPENSSL_HOME)\lib" libcrypto.lib libssl.lib ws2_32.lib crypt32.lib advapi32.lib user32.lib

$(JGSKIT_RC_OBJ) : $(JGSKIT_RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(JGSKIT_RC_SRC)

OpenSSLNativeInterface.obj : openssl\OpenSSLNativeInterface.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-Iopenssl \
		openssl\OpenSSLNativeInterface.c

OpenSSLSymmetricCipher.obj : openssl\OpenSSLSymmetricCipher.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-Iopenssl \
		openssl\OpenSSLSymmetricCipher.c

OpenSSLGCM.obj : openssl\OpenSSLGCM.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I..\include \
		-Iopenssl \
		openssl\OpenSSLGCM.c
		
OpenSSLCCM.obj : openssl\OpenSSLCCM.c openssl\OpenSSLHelpers.h
    cl \
        $(DEBUG_FLAGS) \
        $(CFLAGS) \
        -c \
        -I"$(OPENSSL_HOME)\include" \
        -I"$(JAVA_HOME)\include" \
        -I"$(JAVA_HOME)\include\win32" \
        -I..\include \
        -Iopenssl \
        openssl\OpenSSLCCM.c

OpenSSLKeyWrap.obj : openssl\OpenSSLKeyWrap.c openssl\OpenSSLHelpers.h
    cl \
        $(DEBUG_FLAGS) \
        $(CFLAGS) \
        -c \
        -I"$(OPENSSL_HOME)\include" \
        -I"$(JAVA_HOME)\include" \
        -I"$(JAVA_HOME)\include\win32" \
        -I..\include \
        -Iopenssl \
        openssl\OpenSSLKeyWrap.c
                		
OpenSSLDigest.obj : openssl\OpenSSLDigest.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I..\include \
		-Iopenssl \
		openssl\OpenSSLDigest.c

OpenSSLHMAC.obj : openssl\OpenSSLHMAC.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I..\include \
		-Iopenssl \
		openssl\OpenSSLHMAC.c

OpenSSLPBKDF2.obj : openssl\OpenSSLPBKDF2.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I..\include \
		-Iopenssl \
		openssl\OpenSSLPBKDF2.c

OpenSSLHKDF.obj : openssl\OpenSSLHKDF.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I..\include \
		-Iopenssl \
		openssl\OpenSSLHKDF.c

OpenSSLUtils.obj : openssl\OpenSSLUtils.c
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-Iopenssl \
		openssl\OpenSSLUtils.c

OpenSSLHelpers.obj : openssl\OpenSSLHelpers.c openssl\OpenSSLHelpers.h
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-Iopenssl \
		openssl\OpenSSLHelpers.c

BuildDate.obj : openssl\BuildDate.c FORCE
	cl \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-Iopenssl \
		openssl\BuildDate.c

FORCE :

$(OBJS) : headers

headers :
	@echo Compiling OpenJCEPlus OpenSSL headers
	$(JAVA_HOME)\bin\javac \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d $(JAVACLASSDIR) \
		-h $(TOPDIR)\src\main\native\openssl\ \
		$(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\openssl\*.java

clean :
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

.PHONY : all clean copy headers