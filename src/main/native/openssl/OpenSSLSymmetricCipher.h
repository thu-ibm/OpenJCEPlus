/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_SYMMETRIC_CIPHER_H
#define _OPENSSL_SYMMETRIC_CIPHER_H

#include <jni.h>
#include <openssl/evp.h>
#include "OpenSSLContext.h"

// Cipher context structure
typedef struct {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int padding;
    int encrypt;  // 1 for encrypt, 0 for decrypt
    int blockSize;  // Cache the block size
    unsigned char *key;
    int keyLen;
    unsigned char *iv;
    int ivLen;
} CipherContext;

// Function prototypes
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1create
  (JNIEnv *env, jclass cls, jlong contextId, jstring cipherName);

JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1init
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jint encrypt, jint paddingId, jbyteArray key, jbyteArray iv);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getBlockSize
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getKeyLength
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getIVLength
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptUpdate
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptUpdate
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptFinal
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit);

JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptFinal
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit);

JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1delete
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId);

#endif 

