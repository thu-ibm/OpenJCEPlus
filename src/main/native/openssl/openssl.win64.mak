###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR       = $(MAKEDIR)\..\..\..\..
PLAT         = opensslwin
CFLAGS       = -nologo -DWINDOWS -MD
CC           = cl

#DEBUG_DETAIL = -DDEBUG_OPENSSL_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_CIPHER_DETAIL
#DEBUG_DATA   = -DDEBUG_OPENSSL_DATA   -DDEBUG_DIGEST_DATA   -DDEBUG_CIPHER_DATA
#DEBUG_FLAGS  = -DDEBUG $(DEBUG_DETAIL) $(DEBUG_DATA)

BUILDTOP     = $(TOPDIR)\target\build$(PLAT)
HOSTOUT      = $(BUILDTOP)\host64
JAVACLASSDIR = $(TOPDIR)\target\classes
NATIVE_DIR   = $(MAKEDIR)
JNI_CLASS    = $(TOPDIR)\src\main\java\com\ibm\crypto\plus\provider\openssl\NativeOpenSSLAdapter.java

OBJS = \
	OpenSSLNativeInterface.obj \
	OpenSSLSymmetricCipher.obj \
	OpenSSLGCM.obj \
	OpenSSLCCM.obj \
	OpenSSLKeyWrap.obj \
	OpenSSLRandom.obj \
	OpenSSLUtils.obj \
	OpenSSLHelpers.obj \
	BuildDate.obj

TARGET = libjgskit_openssl_64.dll

RC_SRC = jgskit_resource.rc
RC_OBJ = jgskit_resource.res

TARGET_LIBS = -LIBPATH:"$(OPENSSL_HOME)\lib" libcrypto.lib libssl.lib ws2_32.lib crypt32.lib advapi32.lib user32.lib

all : displaycompiler copy

$(TARGET) : $(OBJS) $(RC_OBJ)
	link -dll -out:$@ $(OBJS) $(RC_OBJ) $(TARGET_LIBS)

$(RC_OBJ) : $(RC_SRC)
	rc $(BUILD_CFLAGS) -Fo$@ $(RC_SRC)

.c.obj :
	$(CC) \
		$(DEBUG_FLAGS) \
		$(CFLAGS) \
		-c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I. \
		$*.c

# OpenSSLJNI.c compiles to OpenSSLNativeInterface.obj (different stem name).
OpenSSLNativeInterface.obj : OpenSSLJNI.c OpenSSLHelpers.h
	$(CC) $(DEBUG_FLAGS) $(CFLAGS) -c \
		-I"$(OPENSSL_HOME)\include" \
		-I"$(JAVA_HOME)\include" \
		-I"$(JAVA_HOME)\include\win32" \
		-I. \
		OpenSSLJNI.c -Fo$@

displaycompiler :
	@echo "Compiler version: " && $(CC)
	@echo "Building with $(CC) compiler..."
	@echo "-------------------------------------"

copy : $(TARGET)
	-@mkdir -p $(HOSTOUT) 2>nul
	-@cp *.obj $(HOSTOUT)
	-@cp $(RC_OBJ) $(HOSTOUT)
	-@cp $(TARGET) $(HOSTOUT)

# Force BuildDate to be recompiled every time.
BuildDate.obj : FORCE

FORCE :

clean :
	-@del $(HOSTOUT)\*.obj
	-@del $(HOSTOUT)\*.exp
	-@del $(HOSTOUT)\*.lib
	-@del $(HOSTOUT)\*.dll
	-@del $(HOSTOUT)\*.res

.PHONY : all clean copy displaycompiler
