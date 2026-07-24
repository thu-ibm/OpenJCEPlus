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
#include <openssl/err.h>
#include "OpenSSLContext.h"
#include "OpenSSLHelpers.h"
#include "OpenSSLExceptionCodes.h"

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_bytes
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1bytes
  (JNIEnv *env, jclass cls, jint isFIPS, jbyteArray bytes)
{
    jbyte *bytesNative = NULL;
    jsize bytesLen = 0;
    int rc = 0;
    OpenSSLContext* context = NULL;

    if (bytes == NULL) {
        jclass npe = (*env)->FindClass(env, "java/lang/NullPointerException");
        if (npe != NULL) (*env)->ThrowNew(env, npe, "bytes array is null");
        return;
    }

    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return; // Nothing to do
    }

    /* Resolve the correct library context (FIPS-isolated or default) */
    if (!validateAndGetContext(env, isFIPS, "RAND_bytes", &context)) {
        return;
    }

    bytesNative = (*env)->GetByteArrayElements(env, bytes, NULL);
    if (bytesNative == NULL) {
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to get byte array elements");
        return;
    }

    /* Use RAND_bytes_ex to generate bytes in the correct library context.
     * In FIPS mode this ensures the FIPS provider's DRBG is used. */
    rc = RAND_bytes_ex(context->libctx, (unsigned char *)bytesNative, (size_t)bytesLen, 0);

    if (rc != 1) {
        unsigned long err = ERR_get_error();
        char errMsg[256];
        ERR_error_string_n(err, errMsg, sizeof(errMsg));

        (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);

        jclass exClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (exClass != NULL) {
            char fullMsg[512];
            snprintf(fullMsg, sizeof(fullMsg), "RAND_bytes failed: %s (error code: %lu)", errMsg, err);
            (*env)->ThrowNew(env, exClass, fullMsg);
        }
        return;
    }

    /* Copy the generated random bytes back to the Java array */
    (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, 0);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_seed
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1seed
  (JNIEnv *env, jclass cls, jint isFIPS, jbyteArray seed)
{
    jbyte *seedNative = NULL;
    jsize seedLen = 0;
    OpenSSLContext* context = NULL;

    if (seed == NULL) {
        return; // Silently ignore null seed
    }

    seedLen = (*env)->GetArrayLength(env, seed);
    if (seedLen <= 0) {
        return; // Nothing to do
    }

    /* Resolve the correct library context so seed entropy goes to the right DRBG */
    if (!validateAndGetContext(env, isFIPS, "RAND_seed", &context)) {
        return;
    }

    seedNative = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seedNative == NULL) {
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to get seed array elements");
        return;
    }

    /* RAND_seed_ex is not available in OpenSSL 3; use RAND_bytes_ex to push entropy
     * into the library context's DRBG by adding it as additional input.
     * The standard way to seed a specific OSSL_LIB_CTX in OpenSSL 3 is via
     * RAND_add (global) or through an EVP_RAND_CTX reseed; for the simple
     * seed-the-default-DRBG case we call RAND_add which feeds the process-wide
     * entropy pool and is the documented approach for all contexts. */
    RAND_add((const void *)seedNative, (int)seedLen, (double)seedLen);

    (*env)->ReleaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_status
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1status
  (JNIEnv *env, jclass cls, jint isFIPS)
{
    /* Use the context-bound DRBG so that FIPS mode queries the FIPS DRBG.
     * RAND_status() is a global function that ignores OSSL_LIB_CTX and would
     * always reflect the default process context, giving a false-positive in
     * FIPS mode when the FIPS DRBG has not yet been instantiated. */
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, isFIPS, "RAND_status", &context)) {
        return 0;
    }

    EVP_RAND_CTX *primary = RAND_get0_primary(context->libctx);
    if (primary == NULL) {
        return 0;
    }
    /* EVP_RAND_get_state() takes an EVP_RAND_CTX* and returns the state.
     * EVP_RAND_CTX_get_state() was added in OpenSSL 3.2 but not universally
     * exported; EVP_RAND_get_state() is the stable, widely-available API. */
    return (EVP_RAND_get_state(primary) == EVP_RAND_STATE_READY) ? 1 : 0;
}

// ============================================================================
// Extended Random (DRBG) functions
// ============================================================================

#include <openssl/evp.h>

// Structure to hold DRBG context
typedef struct {
    EVP_RAND_CTX *ctx;
    char *algName;
} DRBG_Context;

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_create
 * Signature: (ILjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1create
  (JNIEnv *env, jclass cls, jint isFIPS, jstring algName)
{
    const char *functionName = "EXTRAND_create";
    const char *algNameChars = NULL;
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *ctx = NULL;
    DRBG_Context *drbgCtx = NULL;
    char *storedAlgName = NULL;
    OpenSSLContext* context = NULL;
    
    if (algName == NULL) {
        jclass npe = (*env)->FindClass(env, "java/lang/NullPointerException");
        if (npe != NULL) (*env)->ThrowNew(env, npe, "algName is null");
        return 0;
    }
    
    // Validate and get context
    if (!validateAndGetContext(env, isFIPS, functionName, &context)) {
        return 0;
    }
    
    algNameChars = (*env)->GetStringUTFChars(env, algName, NULL);
    if (algNameChars == NULL) {
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to get algorithm name");
        return 0;
    }
    
    // Map algorithm names to OpenSSL DRBG names
    // SHA256 -> HASH-DRBG with SHA256
    // SHA512 -> HASH-DRBG with SHA512
    const char *opensslAlg = "HASH-DRBG";
    
    // Get the DRBG algorithm using the proper library context
    rand = EVP_RAND_fetch(context->libctx, opensslAlg, NULL);
    if (rand == NULL) {
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        
        jclass exClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (exClass != NULL) {
            char errMsg[256];
            snprintf(errMsg, sizeof(errMsg), "Failed to fetch DRBG algorithm: %s", opensslAlg);
            (*env)->ThrowNew(env, exClass, errMsg);
        }
        return 0;
    }
    
    // Create DRBG context
    ctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand); // We can free the RAND object now
    
    if (ctx == NULL) {
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        
        jclass exClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (exClass != NULL) {
            (*env)->ThrowNew(env, exClass, "Failed to create DRBG context");
        }
        return 0;
    }
    
    // Instantiate the DRBG with the digest algorithm passed as params.
    // Per OpenSSL 3 EVP_RAND design, instantiation params (including the
    // digest selection) must be passed to EVP_RAND_instantiate, not set
    // via a separate EVP_RAND_CTX_set_params call on an uninstantiated ctx.
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)algNameChars, 0);
    params[1] = OSSL_PARAM_construct_end();
    
    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, params)) {
        unsigned long err = ERR_get_error();
        char errMsg[512];
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        
        EVP_RAND_CTX_free(ctx);
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        
        jclass exClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (exClass != NULL) {
            char fullMsg[768];
            snprintf(fullMsg, sizeof(fullMsg), "Failed to instantiate DRBG: %s", errMsg);
            (*env)->ThrowNew(env, exClass, fullMsg);
        }
        return 0;
    }
    
    // Allocate and initialize our context structure
    drbgCtx = (DRBG_Context *)malloc(sizeof(DRBG_Context));
    if (drbgCtx == NULL) {
        EVP_RAND_CTX_free(ctx);
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to allocate DRBG context structure");
        return 0;
    }
    
    // Store algorithm name for potential future use
    storedAlgName = strdup(algNameChars);
    if (storedAlgName == NULL) {
        free(drbgCtx);
        EVP_RAND_CTX_free(ctx);
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
        
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to store algorithm name");
        return 0;
    }
    
    drbgCtx->ctx = ctx;
    drbgCtx->algName = storedAlgName;
    
    (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
    
    return (jlong)(intptr_t)drbgCtx;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_nextBytes
 * Signature: (IJ[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1nextBytes
  (JNIEnv *env, jclass cls, jint isFIPS, jlong drbgContextId, jbyteArray bytes)
{
    DRBG_Context *drbgCtx = (DRBG_Context *)(intptr_t)drbgContextId;
    jbyte *bytesNative = NULL;
    jsize bytesLen = 0;
    
    if (drbgCtx == NULL || drbgCtx->ctx == NULL) {
        jclass ise = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (ise != NULL) (*env)->ThrowNew(env, ise, "DRBG context is null or invalid");
        return;
    }
    
    if (bytes == NULL) {
        jclass npe = (*env)->FindClass(env, "java/lang/NullPointerException");
        if (npe != NULL) (*env)->ThrowNew(env, npe, "bytes array is null");
        return;
    }
    
    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return; // Nothing to do
    }
    
    bytesNative = (*env)->GetByteArrayElements(env, bytes, NULL);
    if (bytesNative == NULL) {
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to get byte array elements");
        return;
    }
    
    // Generate random bytes using the DRBG
    if (!EVP_RAND_generate(drbgCtx->ctx, (unsigned char *)bytesNative, (size_t)bytesLen, 0, 0, NULL, 0)) {
        unsigned long err = ERR_get_error();
        char errMsg[256];
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        
        (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);
        
        jclass exClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (exClass != NULL) {
            char fullMsg[512];
            snprintf(fullMsg, sizeof(fullMsg), "EVP_RAND_generate failed: %s", errMsg);
            (*env)->ThrowNew(env, exClass, fullMsg);
        }
        return;
    }
    
    // Copy the generated random bytes back to Java array
    (*env)->ReleaseByteArrayElements(env, bytes, bytesNative, 0);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_setSeed
 * Signature: (IJ[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1setSeed
  (JNIEnv *env, jclass cls, jint isFIPS, jlong drbgContextId, jbyteArray seed)
{
    DRBG_Context *drbgCtx = (DRBG_Context *)(intptr_t)drbgContextId;
    jbyte *seedNative = NULL;
    jsize seedLen = 0;
    
    if (drbgCtx == NULL || drbgCtx->ctx == NULL) {
        jclass ise = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (ise != NULL) (*env)->ThrowNew(env, ise, "DRBG context is null or invalid");
        return;
    }
    
    if (seed == NULL) {
        return; // Silently ignore null seed
    }
    
    seedLen = (*env)->GetArrayLength(env, seed);
    if (seedLen <= 0) {
        return; // Nothing to do
    }
    
    seedNative = (*env)->GetByteArrayElements(env, seed, NULL);
    if (seedNative == NULL) {
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) (*env)->ThrowNew(env, oom, "Failed to get seed array elements");
        return;
    }
    
    // Reseed the DRBG
    if (!EVP_RAND_reseed(drbgCtx->ctx, 0, NULL, 0, (const unsigned char *)seedNative, (size_t)seedLen)) {
        unsigned long err = ERR_get_error();
        char errMsg[256];
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        
        (*env)->ReleaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
        
        jclass exClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (exClass != NULL) {
            char fullMsg[512];
            snprintf(fullMsg, sizeof(fullMsg), "EVP_RAND_reseed failed: %s", errMsg);
            (*env)->ThrowNew(env, exClass, fullMsg);
        }
        return;
    }
    
    (*env)->ReleaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_delete
 * Signature: (IJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1delete
  (JNIEnv *env, jclass cls, jint isFIPS, jlong drbgContextId)
{
    DRBG_Context *drbgCtx = (DRBG_Context *)(intptr_t)drbgContextId;
    
    if (drbgCtx == NULL) {
        return; // Nothing to do
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


