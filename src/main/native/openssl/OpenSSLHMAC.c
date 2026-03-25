/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHMAC.c
 * @brief Implementation of HMAC (Hash-based Message Authentication Code).
 *
 * This file implements HMAC operations using OpenSSL's HMAC interface.
 * HMAC provides message authentication using a cryptographic hash function
 * combined with a secret key.
 *
 * Key features:
 * - Multiple hash algorithm support (SHA-1, SHA-2, SHA-3 families)
 * - Streaming operations for large data
 * - Context reuse for multiple HMAC computations
 * - FIPS mode support
 *
 * HMAC is specified in RFC 2104 and FIPS 198-1.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "OpenSSLHMAC.h"
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

//============================================================================
// Helper function to validate HMAC context
//============================================================================
int validateHMACContext(JNIEnv* env, jint fipsFlag, jlong hmacId,
                       const char* functionName,
                       OpenSSLHMACContext** hmacCtx) {
    logFunctionEntry(functionName);

    // Validate FIPS flag
    if (!validateAndGetContext(env, fipsFlag, functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Validate HMAC context pointer
    OpenSSLHMACContext* ctx = (OpenSSLHMACContext*)((intptr_t)hmacId);
    if (ctx == NULL) {
        throwOpenSSLException(env, OPENSSL_HMAC_NULL, "HMAC context is NULL");
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE: HMAC context is NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    // Validate internal structures
    if (ctx->hmacCtx == NULL || ctx->md == NULL) {
        throwOpenSSLException(env, OPENSSL_HMAC_INVALID, "HMAC context is invalid");
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE: HMAC context structures are NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    *hmacCtx = ctx;
    return 1;
}

//============================================================================
// HMAC_create - Create a new HMAC context
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1create(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_create";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Get digest algorithm name
    const char* algoName = getStringUTFCharsSafe(env, digestAlgo, functionName,
                                                  "Digest algorithm name is NULL");
    if (algoName == NULL) {
        return 0;
    }

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC Creating HMAC with algorithm: %s", algoName);
    }
#endif

    const EVP_MD* md = fetchDigestSafe(env, context, algoName, functionName,
                                       OPENSSL_HMAC_INVALID, "Failed to fetch digest algorithm");
    if (md == NULL) {
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return 0;
    }

    cleanupStringUTFChars(env, digestAlgo, algoName);

    // Allocate HMAC context structure (already zeroed by mallocSafe)
    OpenSSLHMACContext* hmacCtx = (OpenSSLHMACContext*)mallocSafe(
        env, sizeof(OpenSSLHMACContext), "Failed to allocate HMAC context");
    if (hmacCtx == NULL) {
        EVP_MD_free((EVP_MD*)md);
        logFunctionExit(functionName);
        return 0;
    }

    // Create HMAC context
    hmacCtx->hmacCtx = createHMACCtxSafe(env, functionName, OPENSSL_HMAC_CTX_NEW_FAILED,
                                         "Failed to create HMAC context");
    if (hmacCtx->hmacCtx == NULL) {
        EVP_MD_free((EVP_MD*)md);
        free(hmacCtx);
        return 0;
    }

    hmacCtx->md = md;
    hmacCtx->macSize = EVP_MD_size(md);

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC Created HMAC context: %p, MAC size: %d",
                    hmacCtx, hmacCtx->macSize);
    }
#endif

    logFunctionExit(functionName);
    return (jlong)((intptr_t)hmacCtx);
}

//============================================================================
// HMAC_init - Initialize HMAC with key
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1init(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId, jbyteArray key,
    jint keyLen) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_init";

    OpenSSLHMACContext* hmacCtx = NULL;
    if (!validateHMACContext(env, fipsFlag, hmacId, functionName, &hmacCtx)) {
        return -1;
    }

    // Validate input parameters
    if (key == NULL || keyLen <= 0) {
        throwOpenSSLException(env, OPENSSL_HMAC_INVALID, "Invalid key parameters");
        logFunctionExit(functionName);
        return -1;
    }

    // Get key bytes
    jbyte* keyBytes = getByteArrayElementsSafe(env, key, functionName, "Failed to get key array");
    if (keyBytes == NULL) {
        return -1;
    }

#ifdef DEBUG_HMAC_DATA
    if (debug) {
        gslogMessage("DETAIL_HMAC Initializing HMAC with key length: %d", keyLen);
        gslogMessageHex((char*)keyBytes, 0, keyLen, 0, 0, NULL);
    }
#endif

    // Initialize HMAC
    int result = HMAC_Init_ex(hmacCtx->hmacCtx, keyBytes, keyLen,
                             hmacCtx->md, NULL);
cleanupByteArray(env, key, keyBytes, JNI_ABORT);


    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_HMAC_INIT_FAILED,
                            "Failed to initialize HMAC");
        logOpenSSLError("HMAC_Init_ex");
        logFunctionExit(functionName);
        return -1;
    }

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// HMAC_update - Update HMAC with data
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1update(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId, jbyteArray data,
    jint offset, jint dataLen) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_update";

    OpenSSLHMACContext* hmacCtx = NULL;
    if (!validateHMACContext(env, fipsFlag, hmacId, functionName, &hmacCtx)) {
        return -1;
    }

    // Validate input
    if (data == NULL) {
        throwOpenSSLException(env, OPENSSL_HMAC_INVALID, "Input data is NULL");
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

#ifdef DEBUG_HMAC_DATA
    if (debug) {
        gslogMessage("DETAIL_HMAC Updating HMAC with %d bytes at offset %d",
                    dataLen, offset);
        gslogMessageHex((char*)(dataBytes + offset), 0, dataLen, 0, 0, NULL);
    }
#endif

    // Update HMAC
    int result = HMAC_Update(hmacCtx->hmacCtx,
                            (unsigned char*)(dataBytes + offset),
                            (size_t)dataLen);
cleanupByteArray(env, data, dataBytes, JNI_ABORT);


    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_HMAC_UPDATE_FAILED,
                            "Failed to update HMAC");
        logOpenSSLError("HMAC_Update");
        logFunctionExit(functionName);
        return -1;
    }

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// HMAC_doFinal - Finalize HMAC into provided array and reset
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1doFinal(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId, jbyteArray output) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_doFinal";

    OpenSSLHMACContext* hmacCtx = NULL;
    if (!validateHMACContext(env, fipsFlag, hmacId, functionName, &hmacCtx)) {
        return -1;
    }

    // Validate output array
    if (output == NULL) {
        throwOpenSSLException(env, OPENSSL_HMAC_INVALID, "Output array is NULL");
        logFunctionExit(functionName);
        return -1;
    }

    jsize outputLen = (*env)->GetArrayLength(env, output);
    if (outputLen < hmacCtx->macSize) {
        throwOpenSSLException(env, OPENSSL_HMAC_INVALID, "Output array too small");
        logFunctionExit(functionName);
        return -1;
    }

    // Get output buffer
    jbyte* outputBuffer = getByteArrayElementsSafe(env, output, functionName, "Failed to get output buffer");
    if (outputBuffer == NULL) {
        return -1;
    }

    // Finalize HMAC
    unsigned int macLen = 0;
    int result = HMAC_Final(hmacCtx->hmacCtx,
                           (unsigned char*)outputBuffer,
                           &macLen);

    cleanupByteArray(env, output, outputBuffer, JNI_TRUE);

    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_HMAC_FINAL_FAILED,
                            "Failed to finalize HMAC");
        logOpenSSLError("HMAC_Final");
        logFunctionExit(functionName);
        return -1;
    }

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC Finalized HMAC, size: %d bytes", macLen);
        gslogMessageHex((char*)outputBuffer, 0, macLen, 0, 0, NULL);
    }
#endif

    // Reset HMAC for reuse (re-initialize with same key and digest)
    if (HMAC_Init_ex(hmacCtx->hmacCtx, NULL, 0, NULL, NULL) != 1) {
        throwOpenSSLException(env, OPENSSL_HMAC_INIT_FAILED,
                            "Failed to reset HMAC");
        logOpenSSLError("HMAC_Init_ex");
        logFunctionExit(functionName);
        return -1;
    }

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// HMAC_size - Get HMAC output size
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1size(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_size";

    OpenSSLHMACContext* hmacCtx = NULL;
    if (!validateHMACContext(env, fipsFlag, hmacId, functionName, &hmacCtx)) {
        return -1;
    }

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC HMAC size: %d bytes", hmacCtx->macSize);
    }
#endif

    logFunctionExit(functionName);
    return hmacCtx->macSize;
}

//============================================================================
// HMAC_reset - Reset HMAC to initial state
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_reset";

    OpenSSLHMACContext* hmacCtx = NULL;
    if (!validateHMACContext(env, fipsFlag, hmacId, functionName, &hmacCtx)) {
        return;
    }

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC Resetting HMAC context: %p", hmacCtx);
    }
#endif

    // Reset HMAC (keeps key and digest, clears accumulated data)
    if (HMAC_Init_ex(hmacCtx->hmacCtx, NULL, 0, NULL, NULL) != 1) {
        throwOpenSSLException(env, OPENSSL_HMAC_INIT_FAILED,
                            "Failed to reset HMAC");
        logOpenSSLError("HMAC_Init_ex");
    }

    logFunctionExit(functionName);
}

//============================================================================
// HMAC_delete - Delete HMAC context and free resources
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId) {
    static const char* functionName = "OpenSSLNativeInterface.HMAC_delete";
    logFunctionEntry(functionName);

    OpenSSLHMACContext* hmacCtx = (OpenSSLHMACContext*)((intptr_t)hmacId);
    if (hmacCtx == NULL) {
        logFunctionExit(functionName);
        return;
    }

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC Deleting HMAC context: %p", hmacCtx);
    }
#endif

    // Free HMAC context
    if (hmacCtx->hmacCtx != NULL) {
        HMAC_CTX_free(hmacCtx->hmacCtx);
        hmacCtx->hmacCtx = NULL;
    }

    // Free the EVP_MD that was fetched with EVP_MD_fetch
    if (hmacCtx->md != NULL) {
        EVP_MD_free((EVP_MD*)hmacCtx->md);
        hmacCtx->md = NULL;
    }
// Free structure
free(hmacCtx);

logFunctionExit(functionName);
}


