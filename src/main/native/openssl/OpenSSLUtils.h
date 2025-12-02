/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_UTILS_H
#define _OPENSSL_UTILS_H

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"

// Success and failure codes
#define OPENSSL_SUCCESS 0
#define OPENSSL_FAILURE -1

// Macro to free memory and set pointer to NULL
#define FREE_AND_NULL(ptr) \
    if ((ptr) != NULL) { \
        free((ptr)); \
        (ptr) = NULL; \
    }

// Debug flag
extern int debug;

// Function prototypes
void throwOpenSSLException(JNIEnv *env, int code, const char *msg);
char *getOpenSSLErrorString(void);
void logOpenSSLError(const char *prefix);
void logMessage(const char *format, ...);
void logFunctionEntry(const char *functionName);
void logFunctionExit(const char *functionName);
void logHexData(const unsigned char *data, int length, const char *prefix);

// JNI class and method references
jclass getOpenSSLExceptionClass(JNIEnv *env);

#endif 
