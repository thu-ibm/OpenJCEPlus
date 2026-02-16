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

#define OPENSSL_SUCCESS 0
#define OPENSSL_FAILURE -1

#define FREE_AND_NULL(ptr) \
    if ((ptr) != NULL) {   \
        free((ptr));       \
        (ptr) = NULL;      \
    }

extern int debug;

void  throwOpenSSLException(JNIEnv* env, int code, const char* msg);
char* getOpenSSLErrorString(void);
void  logOpenSSLError(const char* prefix);
void  logHexData(const unsigned char* data, int length, const char* prefix);

jclass getOpenSSLExceptionClass(JNIEnv* env);

OpenSSLContext* getOrCreateContext(JNIEnv* env, int isFIPS);

void cleanupByteArrays(JNIEnv*    env,
                       jbyteArray keyArray,
                       jbyte*     keyBytes,
                       jbyteArray ivArray,
                       jbyte*     ivBytes);

void cleanupIOArrays(JNIEnv*    env,
                     jbyteArray inputArray,
                     jbyte*     inputBytes,
                     jbyteArray outputArray,
                     jbyte*     outputBytes,
                     jboolean   commitOutput);

#endif
