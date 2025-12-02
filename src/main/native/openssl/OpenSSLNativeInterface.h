/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_NATIVE_INTERFACE_H
#define _OPENSSL_NATIVE_INTERFACE_H

#include <jni.h>

// Context management function prototypes
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_initializeOpenSSL
  (JNIEnv *env, jclass cls);

JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_cleanupOpenSSL
  (JNIEnv *env, jclass cls, jlong contextId);

JNIEXPORT jstring JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CTX_1getValue
  (JNIEnv *env, jclass cls, jlong contextId, jint valueId);

#endif 

