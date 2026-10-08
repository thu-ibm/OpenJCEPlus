/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"

// ============================================================================
// BasicRandom (global DRBG) functions
// Not currently called from the Java provider (BasicRandom has no call
// sites), but implemented so the JNI symbols declared in
// NativeOpenSSLImplementation resolve.
// ============================================================================

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_nextBytes
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1nextBytes(
    JNIEnv *env, jclass cls, jlong osslContextId, jbyteArray bytes)
{
    jbyte *bytesNative = NULL;
    jsize  bytesLen    = 0;

    if (bytes == NULL) {
        throwOSSLException(env, 0, "RAND_nextBytes: bytes array is null");
        return;
    }

    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return;
    }

    bytesNative = (*env)->GetByteArrayElements(env, bytes, NULL);
    if (bytesNative == NULL) {
        throwOSSLException(env, 0, "RAND_nextBytes: GetByteArrayElements failed");
        return;
    }

    if (RAND_bytes((unsigned char *)bytesNative, (int)bytesLen) != 1) {
        unsigned long err = ERR_get_error();
        char msg[256];
        ERR_error_string_n(err, msg, sizeof(msg));
        (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);
        throwOSSLException(env, 0, msg);
        return;
    }

    (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, 0);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_setSeed
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1setSeed(
    JNIEnv *env, jclass cls, jlong osslContextId, jbyteArray seed)
{
    jbyte *seedNative = NULL;
    jsize  seedLen    = 0;

    if (seed == NULL) {
        return; /* silently ignore null seed */
    }

    seedLen = (*env)->GetArrayLength(env, seed);
    if (seedLen <= 0) {
        return;
    }

    seedNative = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seedNative == NULL) {
        throwOSSLException(env, 0, "RAND_setSeed: GetByteArrayElements failed");
        return;
    }

    RAND_add((const void *)seedNative, (int)seedLen, (double)seedLen);

    (*env)->ReleaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_generateSeed
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1generateSeed(
    JNIEnv *env, jclass cls, jlong osslContextId, jbyteArray bytes)
{
    jbyte *bytesNative = NULL;
    jsize  bytesLen    = 0;

    if (bytes == NULL) {
        throwOSSLException(env, 0, "RAND_generateSeed: bytes array is null");
        return;
    }

    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return;
    }

    bytesNative = (*env)->GetByteArrayElements(env, bytes, NULL);
    if (bytesNative == NULL) {
        throwOSSLException(env, 0, "RAND_generateSeed: GetByteArrayElements failed");
        return;
    }

    if (RAND_bytes((unsigned char *)bytesNative, (int)bytesLen) != 1) {
        unsigned long err = ERR_get_error();
        char msg[256];
        ERR_error_string_n(err, msg, sizeof(msg));
        (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);
        throwOSSLException(env, 0, msg);
        return;
    }

    (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, 0);
}

// ============================================================================
// ExtendedRandom (per-instance HASH-DRBG) functions
// ============================================================================

/* Internal structure holding a HASH-DRBG instance */
typedef struct {
    EVP_RAND_CTX *ctx;
    char         *algName;
} DRBG_Context;

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1create(
    JNIEnv *env, jclass cls, jlong osslContextId, jstring algName)
{
    const char   *algNameChars  = NULL;
    const char   *digestName    = NULL;
    EVP_RAND     *rand          = NULL;
    EVP_RAND_CTX *ctx           = NULL;
    DRBG_Context *drbgCtx       = NULL;
    char         *storedAlgName = NULL;

    if (algName == NULL) {
        throwOSSLException(env, 0, "EXTRAND_create: algName is null");
        return 0;
    }

    algNameChars = (*env)->GetStringUTFChars(env, algName, NULL);
    if (algNameChars == NULL) {
        throwOSSLException(env, 0, "EXTRAND_create: GetStringUTFChars failed");
        return 0;
    }

    /*
     * Map the Java algorithm name (e.g. "SHA256") to the EVP digest name
     * expected by OpenSSL's HASH-DRBG ("digest" param must be an EVP_MD name).
     */
    if (strcmp(algNameChars, "SHA256") == 0) {
        digestName = "SHA-256";
    } else if (strcmp(algNameChars, "SHA512") == 0) {
        digestName = "SHA-512";
    } else {
        digestName = algNameChars; /* pass through for any future algorithm */
    }

    rand = EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
    if (rand == NULL) {
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        throwOSSLException(env, 0, "EXTRAND_create: EVP_RAND_fetch(HASH-DRBG) failed");
        return 0;
    }

    ctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    rand = NULL;

    if (ctx == NULL) {
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        throwOSSLException(env, 0, "EXTRAND_create: EVP_RAND_CTX_new failed");
        return 0;
    }

    /*
     * Instantiate the DRBG.  The digest selection must be passed at
     * instantiation time via EVP_RAND_instantiate params (OpenSSL 3 design).
     */
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digestName, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, params)) {
        unsigned long err = ERR_get_error();
        char msg[512];
        ERR_error_string_n(err, msg, sizeof(msg));
        EVP_RAND_CTX_free(ctx);
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        throwOSSLException(env, 0, msg);
        return 0;
    }

    drbgCtx = (DRBG_Context *)malloc(sizeof(DRBG_Context));
    if (drbgCtx == NULL) {
        EVP_RAND_CTX_free(ctx);
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        throwOSSLException(env, 0, "EXTRAND_create: malloc(DRBG_Context) failed");
        return 0;
    }

    storedAlgName = strdup(algNameChars);
    if (storedAlgName == NULL) {
        free(drbgCtx);
        EVP_RAND_CTX_free(ctx);
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        throwOSSLException(env, 0, "EXTRAND_create: strdup(algName) failed");
        return 0;
    }

    drbgCtx->ctx     = ctx;
    drbgCtx->algName = storedAlgName;

    (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
    return (jlong)(intptr_t)drbgCtx;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_nextBytes
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1nextBytes(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId, jbyteArray bytes)
{
    DRBG_Context *drbgCtx    = (DRBG_Context *)(intptr_t)drbgContextId;
    jbyte        *bytesNative = NULL;
    jsize         bytesLen   = 0;

    if (drbgCtx == NULL || drbgCtx->ctx == NULL) {
        throwOSSLException(env, 0, "EXTRAND_nextBytes: DRBG context is null");
        return;
    }
    if (bytes == NULL) {
        throwOSSLException(env, 0, "EXTRAND_nextBytes: bytes array is null");
        return;
    }

    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return;
    }

    bytesNative = (*env)->GetByteArrayElements(env, bytes, NULL);
    if (bytesNative == NULL) {
        throwOSSLException(env, 0, "EXTRAND_nextBytes: GetByteArrayElements failed");
        return;
    }

    if (!EVP_RAND_generate(drbgCtx->ctx, (unsigned char *)bytesNative, (size_t)bytesLen, 0, 0, NULL, 0)) {
        unsigned long err = ERR_get_error();
        char msg[256];
        ERR_error_string_n(err, msg, sizeof(msg));
        (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);
        throwOSSLException(env, 0, msg);
        return;
    }

    (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, 0);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_setSeed
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1setSeed(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId, jbyteArray seed)
{
    DRBG_Context *drbgCtx   = (DRBG_Context *)(intptr_t)drbgContextId;
    jbyte        *seedNative = NULL;
    jsize         seedLen   = 0;

    if (drbgCtx == NULL || drbgCtx->ctx == NULL) {
        throwOSSLException(env, 0, "EXTRAND_setSeed: DRBG context is null");
        return;
    }
    if (seed == NULL) {
        return; /* silently ignore null seed */
    }

    seedLen = (*env)->GetArrayLength(env, seed);
    if (seedLen <= 0) {
        return;
    }

    seedNative = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seedNative == NULL) {
        throwOSSLException(env, 0, "EXTRAND_setSeed: GetByteArrayElements failed");
        return;
    }

    if (!EVP_RAND_reseed(drbgCtx->ctx, 0, NULL, 0, (const unsigned char *)seedNative, (size_t)seedLen)) {
        unsigned long err = ERR_get_error();
        char msg[256];
        ERR_error_string_n(err, msg, sizeof(msg));
        (*env)->ReleaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
        throwOSSLException(env, 0, msg);
        return;
    }

    (*env)->ReleaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1delete(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId)
{
    DRBG_Context *drbgCtx = (DRBG_Context *)(intptr_t)drbgContextId;

    if (drbgCtx == NULL) {
        return;
    }

    if (drbgCtx->ctx != NULL) {
        EVP_RAND_CTX_free(drbgCtx->ctx);
        drbgCtx->ctx = NULL;
    }

    if (drbgCtx->algName != NULL) {
        free(drbgCtx->algName);
        drbgCtx->algName = NULL;
    }

    free(drbgCtx);
}
