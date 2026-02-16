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

typedef struct {
    EVP_CIPHER_CTX*   ctx;
    const EVP_CIPHER* cipher;
    int               padding;
    int               encrypt;
    int               blockSize;
    unsigned char*    key;
    int               keyLen;
    unsigned char*    iv;
    int               ivLen;
    int               tagLen;
} CipherContext;

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1create(
    JNIEnv* env, jclass cls, jlong contextId, jstring cipherName);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_init
 * Signature: (JJII[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1init(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jint paddingId, jbyteArray key, jbyteArray iv);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getBlockSize(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getKeyLength(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getIVLength(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_encryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptUpdate(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_decryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptUpdate(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_encryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_decryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1delete(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId);

#endif
