/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_CCM_H
#define _OPENSSL_CCM_H

#include <jni.h>

// CCM constants
#define MAX_CCM_TAG_SIZE 16
#define MIN_CCM_TAG_SIZE 4
#define MAX_CCM_IV_SIZE 13
#define MIN_CCM_IV_SIZE 7
#define OPENSSL_TAG_MISMATCH_ERROR -6

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1init(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_update
 * Signature: (JJII[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1update(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_encryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_decryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen);

#endif 