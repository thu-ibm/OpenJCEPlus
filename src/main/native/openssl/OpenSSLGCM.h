/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_GCM_H
#define _OPENSSL_GCM_H

#include <jni.h>

// GCM constants
#define MAX_GCM_TAG_SIZE 16
#define MIN_GCM_TAG_SIZE 4
#define MAX_GCM_IV_SIZE 1024
#define MIN_GCM_IV_SIZE 1
#define OPENSSL_TAG_MISMATCH_ERROR -6

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1init(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_update
 * Signature: (JJII[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1update(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_encryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_decryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen);

#endif
