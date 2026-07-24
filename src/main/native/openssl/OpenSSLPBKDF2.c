/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLPBKDF2.c
 * @brief Implementation of PBKDF2 (Password-Based Key Derivation Function 2).
 *
 * This file implements PBKDF2 as specified in RFC 8018 (PKCS #5 v2.1).
 * PBKDF2 derives cryptographic keys from passwords using a pseudorandom
 * function (HMAC with a specified hash algorithm).
 *
 * The function applies HMAC iteratively to increase computational cost,
 * making brute-force attacks more difficult. A random salt is used to
 * prevent rainbow table attacks.
 *
 * Security considerations:
 * - Use strong hash algorithms (SHA-256 or better)
 * - Use random salts of at least 16 bytes
 * - Use high iteration counts (10,000+ minimum, 600,000+ recommended)
 * - Never reuse salts across different passwords
 *
 * PBKDF2 is widely used for password hashing and key derivation in
 * applications like disk encryption, password storage, and key wrapping.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"
#include "OpenSSLLogging.h"

//============================================================================
// PBKDF2_derive - Derive key using PBKDF2
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_PBKDF2_1derive(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo,
    jbyteArray password, jbyteArray salt, jint iterations, jint keyLength) {
    static const char* functionName = "OpenSSLNativeInterface.PBKDF2_derive";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return NULL;
    }

    // Get digest algorithm name
    const char* algoName = getStringUTFCharsSafe(
        env, digestAlgo, functionName, "Digest algorithm name is NULL");
    if (algoName == NULL) {
        return NULL;
    }

#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_PBKDF2 Algorithm: %s, Iterations: %d, KeyLength: %d",
            algoName, iterations, keyLength);
    }
#endif

    // Get password bytes
    jbyte* passwordBytes = getByteArrayElementsSafe(env, password, functionName,
                                                    "Password is NULL");
    if (passwordBytes == NULL) {
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return NULL;
    }
    jsize passwordLen = (*env)->GetArrayLength(env, password);

    // Get salt bytes
    jbyte* saltBytes =
        getByteArrayElementsSafe(env, salt, functionName, "Salt is NULL");
    if (saltBytes == NULL) {
        cleanupByteArray(env, password, passwordBytes, JNI_ABORT);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return NULL;
    }
    jsize saltLen = (*env)->GetArrayLength(env, salt);

    // Allocate output buffer
    unsigned char* derivedKey = (unsigned char*)mallocSafe(
        env, keyLength, "Failed to allocate memory for derived key");
    if (derivedKey == NULL) {
        cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        cleanupByteArray(env, password, passwordBytes, JNI_ABORT);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        logFunctionExit(functionName);
        return NULL;
    }

    // Fetch KDF
#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_PBKDF2 About to fetch PBKDF2 KDF, context=%p, libctx=%p",
            context, context ? context->libctx : NULL);
    }
#endif

    EVP_KDF* kdf =
        fetchKDFSafe(env, context, "PBKDF2", functionName,
                     OPENSSL_PBKDF2_FAILED, "Failed to fetch PBKDF2");
    if (kdf == NULL) {
        free(derivedKey);
        cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        cleanupByteArray(env, password, passwordBytes, JNI_ABORT);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return NULL;
    }

#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage("DETAIL_PBKDF2 Successfully fetched PBKDF2 KDF=%p", kdf);
    }
#endif

#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage("DETAIL_PBKDF2 About to create KDF context");
    }
#endif

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);  /* kdf ref no longer needed once kctx is created */
    kdf = NULL;

#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage("DETAIL_PBKDF2 Created KDF context=%p", kctx);
    }
#endif

    if (kctx == NULL) {
        free(derivedKey);
        cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        cleanupByteArray(env, password, passwordBytes, JNI_ABORT);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_PBKDF2_FAILED,
                              "Failed to create PBKDF2 context");
        logOpenSSLError("EVP_KDF_CTX_new");
        logFunctionExit(functionName);
        return NULL;
    }

    // Build parameter array for PBKDF2
    OSSL_PARAM   params[5] = {0};
    unsigned int iter      = (unsigned int)iterations;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, passwordBytes, (size_t)passwordLen);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                  saltBytes, (size_t)saltLen);
    params[2] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char*)algoName, 0);
    params[4] = OSSL_PARAM_construct_end();

    // Perform derivation
#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_PBKDF2 About to call EVP_KDF_derive: kctx=%p, "
            "derivedKey=%p, keyLength=%d",
            kctx, derivedKey, keyLength);
        gslogMessage(
            "DETAIL_PBKDF2 Params: password=%p (len=%d), salt=%p (len=%d), "
            "iter=%u, digest=%s",
            passwordBytes, passwordLen, saltBytes, saltLen,
            (unsigned int)iterations, algoName);
    }
#endif

    int result = EVP_KDF_derive(kctx, derivedKey, (size_t)keyLength, params);

#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage("DETAIL_PBKDF2 EVP_KDF_derive returned: %d", result);
    }
#endif

    // Clean up contexts (kdf was already freed after EVP_KDF_CTX_new)
    EVP_KDF_CTX_free(kctx);

    if (result != 1) {
        // Clean up on error
        cleanupByteArray(env, password, passwordBytes, JNI_ABORT);
        cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        cleanupStringUTFChars(env, digestAlgo, algoName);
        free(derivedKey);
        setPendingOpenSSLException(env, OPENSSL_PBKDF2_FAILED,
                              "PBKDF2 derivation failed");
        logOpenSSLError("EVP_KDF_derive(PBKDF2)");
        logFunctionExit(functionName);
        return NULL;
    }

    // Clean up after successful derivation
    cleanupByteArray(env, password, passwordBytes, JNI_ABORT);
    cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
    cleanupStringUTFChars(env, digestAlgo, algoName);

#ifdef DEBUG_PBKDF2_DETAIL
    if (debug) {
        gslogMessage("DETAIL_PBKDF2 Derived key:");
        gslogMessageHex((char*)derivedKey, 0, keyLength, 0, 0, NULL);
    }
#endif

    // Create Java byte array for result
    jbyteArray result_array =
        newByteArraySafe(env, keyLength, "Failed to create result array");
    if (result_array == NULL) {
        free(derivedKey);
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result_array, 0, keyLength,
                               (jbyte*)derivedKey);
    free(derivedKey);

    logFunctionExit(functionName);
    return result_array;
}
