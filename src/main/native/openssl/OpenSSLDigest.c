/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLDigest.c
 * @brief Implementation of cryptographic hash/digest operations using OpenSSL.
 *
 * This file implements message digest (hash) operations using OpenSSL's EVP
 * interface. It supports various hash algorithms including SHA-1, SHA-2 family
 * (SHA-224, SHA-256, SHA-384, SHA-512), and SHA-3 family.
 *
 * Key features:
 * - Multiple hash algorithm support via EVP interface
 * - Streaming digest operations (update multiple times)
 * - Context cloning for branching digest computations
 * - Efficient memory management with context reuse
 * - FIPS mode support
 *
 * The implementation uses OpenSSL 3.0+ EVP_MD API with proper context
 * management and reference counting to prevent memory leaks.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "OpenSSLDigest.h"
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

//============================================================================
// Helper function to validate digest context
//============================================================================
int validateDigestContext(JNIEnv* env, jint fipsFlag, jlong digestId,
                         const char* functionName,
                         OpenSSLDigestContext** digestCtx) {
    logFunctionEntry(functionName);

    // Validate FIPS flag
    if (!validateAndGetContext(env, fipsFlag, functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Validate digest context pointer
    OpenSSLDigestContext* ctx = (OpenSSLDigestContext*)((intptr_t)digestId);
    if (ctx == NULL) {
        throwOpenSSLException(env, OPENSSL_DIGEST_NULL, "Digest context is NULL");
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE: Digest context is NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    // Validate internal structures
    if (ctx->mdCtx == NULL || ctx->md == NULL) {
        throwOpenSSLException(env, OPENSSL_DIGEST_INVALID, "Digest context is invalid");
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE: Digest context structures are NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    *digestCtx = ctx;
    return 1;
}

//============================================================================
// DIGEST_create - Create a new digest context
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1create(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_create";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Get algorithm name
    const char* algoName = getStringUTFCharsSafe(env, digestAlgo, functionName,
                                                  "Digest algorithm name is NULL");
    if (algoName == NULL) {
        return 0;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Creating digest for algorithm: %s, FIPS: %d",
                    algoName, isFIPS);
    }
#endif

    // Allocate digest context structure (already zeroed by mallocSafe)
    OpenSSLDigestContext* digestCtx = (OpenSSLDigestContext*)mallocSafe(
        env, sizeof(OpenSSLDigestContext), "Failed to allocate digest context");
    if (digestCtx == NULL) {
        cleanupStringUTFChars(env, digestAlgo, algoName);
        logFunctionExit(functionName);
        return 0;
    }

    // Fetch digest algorithm
    digestCtx->md = fetchDigestSafe(env, context, algoName, functionName,
                                    OPENSSL_DIGEST_ALGORITHM_NOT_FOUND,
                                    "Failed to fetch digest algorithm");
    if (digestCtx->md == NULL) {
        free(digestCtx);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return 0;
    }

    // Create digest context
    digestCtx->mdCtx = createMDCtxSafe(env, functionName, OPENSSL_DIGEST_CTX_NEW_FAILED,
                                       "Failed to create digest context");
    if (digestCtx->mdCtx == NULL) {
        EVP_MD_free((EVP_MD*)digestCtx->md);
        free(digestCtx);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return 0;
    }

    // Initialize digest
    if (EVP_DigestInit_ex2(digestCtx->mdCtx, digestCtx->md, NULL) != 1) {
        EVP_MD_CTX_free(digestCtx->mdCtx);
        EVP_MD_free((EVP_MD*)digestCtx->md);
        free(digestCtx);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        throwOpenSSLException(env, OPENSSL_DIGEST_INIT_FAILED,
                            "Failed to initialize digest");
        logOpenSSLError("EVP_DigestInit_ex2");
        logFunctionExit(functionName);
        return 0;
    }

    // Get digest size
    digestCtx->digestSize = EVP_MD_get_size(digestCtx->md);

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Created digest context: %p, size: %d bytes",
                    digestCtx, digestCtx->digestSize);
    }
#endif

    cleanupStringUTFChars(env, digestAlgo, algoName);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)digestCtx);
}

//============================================================================
// DIGEST_copy - Create a copy of an existing digest context
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1copy(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_copy";

    OpenSSLDigestContext* srcCtx = NULL;
    if (!validateDigestContext(env, fipsFlag, digestId, functionName, &srcCtx)) {
        return 0;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Copying digest context: %p", srcCtx);
    }
#endif

    // Allocate new digest context (already zeroed by mallocSafe)
    OpenSSLDigestContext* dstCtx = (OpenSSLDigestContext*)mallocSafe(
        env, sizeof(OpenSSLDigestContext), "Failed to allocate digest context for copy");
    if (dstCtx == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    // Copy digest algorithm reference - must increment reference count
    // so that both the original and the copy can independently call EVP_MD_free()
    // without causing a double-free / heap corruption (0xC0000374).
    if (EVP_MD_up_ref((EVP_MD*)srcCtx->md) != 1) {
        free(dstCtx);
        throwOpenSSLException(env, OPENSSL_DIGEST_COPY_FAILED,
                            "Failed to increment digest reference count");
        logOpenSSLError("EVP_MD_up_ref");
        logFunctionExit(functionName);
        return 0;
    }
    dstCtx->md = srcCtx->md;
    dstCtx->digestSize = srcCtx->digestSize;

    // Create new digest context
    dstCtx->mdCtx = createMDCtxSafe(env, functionName, OPENSSL_DIGEST_CTX_NEW_FAILED,
                                    "Failed to create digest context for copy");
    if (dstCtx->mdCtx == NULL) {
        EVP_MD_free((EVP_MD*)dstCtx->md);
        free(dstCtx);
        return 0;
    }

    // Copy digest state
    if (EVP_MD_CTX_copy_ex(dstCtx->mdCtx, srcCtx->mdCtx) != 1) {
        EVP_MD_CTX_free(dstCtx->mdCtx);
        EVP_MD_free((EVP_MD*)dstCtx->md);  // release the up_ref taken above
        free(dstCtx);
        throwOpenSSLException(env, OPENSSL_DIGEST_COPY_FAILED,
                            "Failed to copy digest context");
        logOpenSSLError("EVP_MD_CTX_copy_ex");
        logFunctionExit(functionName);
        return 0;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Created digest copy: %p", dstCtx);
    }
#endif

    logFunctionExit(functionName);
    return (jlong)((intptr_t)dstCtx);
}

//============================================================================
// DIGEST_update - Update digest with data
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1update(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId, jbyteArray data,
    jint offset, jint dataLen) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_update";

    OpenSSLDigestContext* digestCtx = NULL;
    if (!validateDigestContext(env, fipsFlag, digestId, functionName, &digestCtx)) {
        return -1;
    }

    // Validate input
    if (data == NULL) {
        throwOpenSSLException(env, OPENSSL_DIGEST_INVALID, "Input data is NULL");
        logFunctionExit(functionName);
        return -1;
    }

    if (dataLen == 0) {
        logFunctionExit(functionName);
        return 1; // Nothing to update
    }

    jsize arrayLen = (*env)->GetArrayLength(env, data);
    if (!validateOffsetAndLength(env, arrayLen, offset, dataLen, functionName, "Invalid data offset/length")) {
        return -1;
    }

    // Get data array
    jbyte* dataBytes = getByteArrayElementsSafe(env, data, functionName, "Failed to get data array");
    if (dataBytes == NULL) {
        return -1;
    }

#ifdef DEBUG_DIGEST_DATA
    if (debug) {
        gslogMessage("DETAIL_DIGEST Updating digest with %d bytes at offset %d",
                    dataLen, offset);
        gslogMessageHex((char*)(dataBytes + offset), 0, dataLen, 0, 0, NULL);
    }
#endif

    // Update digest
    int result = EVP_DigestUpdate(digestCtx->mdCtx,
                                 (unsigned char*)(dataBytes + offset),
                                 (size_t)dataLen);
cleanupByteArray(env, data, dataBytes, JNI_ABORT);


    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_DIGEST_UPDATE_FAILED,
                            "Failed to update digest");
        logOpenSSLError("EVP_DigestUpdate");
        logFunctionExit(functionName);
        return -1;
    }

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// DIGEST_digest - Finalize digest and return hash
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1digest(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_digest";

    OpenSSLDigestContext* digestCtx = NULL;
    if (!validateDigestContext(env, fipsFlag, digestId, functionName, &digestCtx)) {
        return NULL;
    }

    // Allocate output array
    jbyteArray digestBytes = newByteArraySafe(env, digestCtx->digestSize,
                                              "Failed to allocate digest output array");
    if (digestBytes == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    // Get output buffer
    jbyte* digestBuffer = getByteArrayElementsSafe(env, digestBytes, functionName,
                                                    "Failed to get digest output buffer");
    if (digestBuffer == NULL) {
        return NULL;
    }

    // Finalize digest
    unsigned int digestLen = 0;
    int result = EVP_DigestFinal_ex(digestCtx->mdCtx,
                                   (unsigned char*)digestBuffer,
                                   &digestLen);

    if (result != 1) {
        cleanupByteArray(env, digestBytes, digestBuffer, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                            "Failed to finalize digest");
        logOpenSSLError("EVP_DigestFinal_ex");
        logFunctionExit(functionName);
        return NULL;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Finalized digest, size: %d bytes", digestLen);
        gslogMessageHex((char*)digestBuffer, 0, digestLen, 0, 0, NULL);
    }
#endif

    cleanupByteArray(env, digestBytes, digestBuffer, JNI_TRUE);

    // Reset digest for reuse
    if (EVP_DigestInit_ex2(digestCtx->mdCtx, digestCtx->md, NULL) != 1) {
        logOpenSSLError("EVP_DigestInit_ex2 (reset after digest)");
    }

    logFunctionExit(functionName);
    return digestBytes;
}

//============================================================================
// DIGEST_digest_and_reset - Finalize digest into provided array and reset
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1digest_1and_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId, jbyteArray output) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_digest_and_reset";

    OpenSSLDigestContext* digestCtx = NULL;
    if (!validateDigestContext(env, fipsFlag, digestId, functionName, &digestCtx)) {
        return -1;
    }

    // Validate output array
    // Validate output array
    if (output == NULL) {
        throwOpenSSLException(env, OPENSSL_DIGEST_INVALID, "Output array is NULL");
        logFunctionExit(functionName);
        return -1;
    }

    jsize outputLen = (*env)->GetArrayLength(env, output);
    if (outputLen < digestCtx->digestSize) {
        throwOpenSSLException(env, OPENSSL_DIGEST_INVALID, "Output array too small");
        logFunctionExit(functionName);
        return -1;
    }

    // Get output buffer
    jbyte* outputBuffer = getByteArrayElementsSafe(env, output, functionName, "Failed to get output buffer");
    if (outputBuffer == NULL) {
        return -1;
    }

    // Finalize digest
    unsigned int digestLen = 0;
    int result = EVP_DigestFinal_ex(digestCtx->mdCtx,
                                   (unsigned char*)outputBuffer,
                                   &digestLen);

    cleanupByteArray(env, output, outputBuffer, JNI_TRUE);

    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                            "Failed to finalize digest");
        logOpenSSLError("EVP_DigestFinal_ex");
        logFunctionExit(functionName);
        return -1;
    }

    // Reset digest
    if (EVP_DigestInit_ex2(digestCtx->mdCtx, digestCtx->md, NULL) != 1) {
        throwOpenSSLException(env, OPENSSL_DIGEST_INIT_FAILED,
                            "Failed to reset digest");
        logOpenSSLError("EVP_DigestInit_ex2");
        logFunctionExit(functionName);
        return -1;
    }

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// DIGEST_size - Get digest output size
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1size(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_size";

    OpenSSLDigestContext* digestCtx = NULL;
    if (!validateDigestContext(env, fipsFlag, digestId, functionName, &digestCtx)) {
        return -1;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Digest size: %d bytes", digestCtx->digestSize);
    }
#endif

    logFunctionExit(functionName);
    return digestCtx->digestSize;
}

//============================================================================
// DIGEST_reset - Reset digest to initial state
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_reset";

    OpenSSLDigestContext* digestCtx = NULL;
    if (!validateDigestContext(env, fipsFlag, digestId, functionName, &digestCtx)) {
        return;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Resetting digest context: %p", digestCtx);
    }
#endif

    // Reset digest
    if (EVP_DigestInit_ex2(digestCtx->mdCtx, digestCtx->md, NULL) != 1) {
        throwOpenSSLException(env, OPENSSL_DIGEST_INIT_FAILED,
                            "Failed to reset digest");
        logOpenSSLError("EVP_DigestInit_ex2");
    }

    logFunctionExit(functionName);
}

//============================================================================
// DIGEST_delete - Delete digest context and free resources
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId) {
    static const char* functionName = "OpenSSLNativeInterface.DIGEST_delete";
    logFunctionEntry(functionName);

    OpenSSLDigestContext* digestCtx = (OpenSSLDigestContext*)((intptr_t)digestId);
    if (digestCtx == NULL) {
        logFunctionExit(functionName);
        return;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST Deleting digest context: %p", digestCtx);
    }
#endif

    // Free digest context
    if (digestCtx->mdCtx != NULL) {
        EVP_MD_CTX_free(digestCtx->mdCtx);
        digestCtx->mdCtx = NULL;
    }

    // Free digest algorithm (only if we fetched it)
    if (digestCtx->md != NULL) {
        EVP_MD_free((EVP_MD*)digestCtx->md);
        digestCtx->md = NULL;
    }
// Free structure
free(digestCtx);

logFunctionExit(functionName);
}


