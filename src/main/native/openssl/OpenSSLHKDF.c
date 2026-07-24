/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHKDF.c
 * @brief Implementation of HKDF (HMAC-based Key Derivation Function).
 *
 * This file implements HKDF operations as specified in RFC 5869.
 * HKDF is a key derivation function that uses HMAC to derive keys
 * from input keying material.
 *
 * HKDF consists of two phases:
 * 1. Extract: Derives a pseudorandom key (PRK) from input keying material
 * 2. Expand: Expands the PRK into output keying material of desired length
 *
 * A combined derive operation performs both extract and expand in one call.
 *
 * Key features:
 * - Multiple hash algorithm support (SHA-256, SHA-384, SHA-512, etc.)
 * - Optional salt for extract phase
 * - Optional context/info for expand phase
 * - FIPS mode support
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

#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

// Use the global debug flag defined in OpenSSLUtils.c
extern int debug;

//============================================================================
// HKDF_extract - Extract pseudorandom key from input keying material
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_HKDF_1extract(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo, jbyteArray salt,
    jbyteArray ikm) {
    static const char* functionName = "OpenSSLNativeInterface.HKDF_extract";
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

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF Extract - Algorithm: %s", algoName);
    }
#endif

    // Get salt bytes (can be NULL)
    jbyte* saltBytes = NULL;
    jsize  saltLen   = 0;
    if (salt != NULL) {
        saltBytes = getByteArrayElementsSafe(env, salt, functionName, "salt");
        if (saltBytes == NULL) {
            cleanupStringUTFChars(env, digestAlgo, algoName);
            return NULL;
        }
        saltLen = (*env)->GetArrayLength(env, salt);
    }

    // Get IKM bytes
    jbyte* ikmBytes =
        getByteArrayElementsSafe(env, ikm, functionName, "IKM is NULL");
    if (ikmBytes == NULL) {
        if (saltBytes != NULL) {
            cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        }
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return NULL;
    }
    jsize ikmLen = (*env)->GetArrayLength(env, ikm);

    // Fetch the digest using library context
    EVP_MD* md = (EVP_MD*)fetchDigestSafe(env, context, algoName, functionName,
                                          OPENSSL_HKDF_EXTRACT_FAILED,
                                          "Failed to fetch digest algorithm");
    if (md == NULL) {
        cleanupByteArray(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        }
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return NULL;
    }

    // Get digest size for PRK
    int            digestSize = EVP_MD_get_size(md);
    unsigned char* prk        = (unsigned char*)mallocSafe(
        env, digestSize, "Failed to allocate memory for PRK");
    if (prk == NULL) {
        EVP_MD_free(md);
        cleanupByteArray(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        }
        cleanupStringUTFChars(env, digestAlgo, algoName);
        logFunctionExit(functionName);
        return NULL;
    }

    // Create KDF context
    EVP_KDF* kdf =
        fetchKDFSafe(env, context, "HKDF", functionName,
                     OPENSSL_HKDF_EXTRACT_FAILED, "Failed to fetch HKDF");
    if (kdf == NULL) {
        free(prk);
        EVP_MD_free(md);
        cleanupByteArray(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        }
        cleanupStringUTFChars(env, digestAlgo, algoName);
        return NULL;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (kctx == NULL) {
        free(prk);
        EVP_MD_free(md);
        cleanupByteArray(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        }
        cleanupStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_EXTRACT_FAILED,
                              "Failed to create HKDF context");
        logOpenSSLError("EVP_KDF_CTX_new");
        logFunctionExit(functionName);
        return NULL;
    }

    // Set up parameters for extract
    OSSL_PARAM params[5] = {0};
    int        mode      = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char*)algoName, 0);
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikmBytes, ikmLen);

    if (saltBytes != NULL && saltLen > 0) {
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                      saltBytes, saltLen);
        params[4] = OSSL_PARAM_construct_end();
    } else {
        params[3] = OSSL_PARAM_construct_end();
    }

    // Perform extract
    size_t prkLen = digestSize;
    int    result = EVP_KDF_derive(kctx, prk, prkLen, params);

    // Clean up contexts
    EVP_KDF_CTX_free(kctx);
    EVP_MD_free(md);

    if (result != 1) {
        // Clean up on error
        cleanupByteArray(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
        }
        cleanupStringUTFChars(env, digestAlgo, algoName);
        free(prk);
        setPendingOpenSSLException(env, OPENSSL_HKDF_EXTRACT_FAILED,
                              "HKDF extract failed");
        logOpenSSLError("EVP_KDF_derive");
        logFunctionExit(functionName);
        return NULL;
    }

    // Clean up after successful derivation
    cleanupByteArray(env, ikm, ikmBytes, JNI_ABORT);
    if (saltBytes != NULL) {
        cleanupByteArray(env, salt, saltBytes, JNI_ABORT);
    }
    cleanupStringUTFChars(env, digestAlgo, algoName);

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF Extracted PRK:");
        gslogMessageHex((char*)prk, 0, prkLen, 0, 0, NULL);
    }
#endif

    // Create Java byte array for result
    jbyteArray result_array =
        newByteArraySafe(env, prkLen, "Failed to create result array");
    if (result_array == NULL) {
        free(prk);
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result_array, 0, prkLen, (jbyte*)prk);
    free(prk);

    logFunctionExit(functionName);
    return result_array;
}

//============================================================================
// HKDF_expand - Expand pseudorandom key to desired length
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_HKDF_1expand(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo, jbyteArray prk,
    jbyteArray info, jint length) {
    static const char* functionName = "OpenSSLNativeInterface.HKDF_expand";
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

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF Expand - Algorithm: %s, Length: %d", algoName,
                     length);
    }
#endif

    // Get PRK bytes
    jbyte* prkBytes = getByteArrayElementsSafe(env, prk, functionName, "PRK is NULL");
    if (prkBytes == NULL) {
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        logFunctionExit(functionName);
        return NULL;
    }
    jsize prkLen = (*env)->GetArrayLength(env, prk);

    // Get info bytes (can be NULL)
    jbyte* infoBytes = NULL;
    jsize  infoLen   = 0;
    if (info != NULL) {
        infoBytes = getByteArrayElementsSafe(env, info, functionName, "info");
        if (infoBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
            (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
            logFunctionExit(functionName);
            return NULL;
        }
        infoLen = (*env)->GetArrayLength(env, info);
    }

    // Allocate output buffer (already zeroed by mallocSafe)
    unsigned char* okm = (unsigned char*)mallocSafe(
        env, length, "Failed to allocate memory for OKM");
    if (okm == NULL) {
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        logFunctionExit(functionName);
        return NULL;
    }

    // Fetch the digest using library context
    EVP_MD* md = EVP_MD_fetch(context->libctx, algoName, NULL);
    if (md == NULL) {
        free(okm);
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_EXPAND_FAILED,
                              "Failed to fetch digest algorithm");
        logOpenSSLError("EVP_MD_fetch");
        logFunctionExit(functionName);
        return NULL;
    }

    // Create KDF context
    EVP_KDF* kdf = EVP_KDF_fetch(context->libctx, "HKDF", NULL);
    if (kdf == NULL) {
        EVP_MD_free(md);
        free(okm);
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_EXPAND_FAILED,
                              "Failed to fetch HKDF");
        logOpenSSLError("EVP_KDF_fetch");
        logFunctionExit(functionName);
        return NULL;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (kctx == NULL) {
        EVP_MD_free(md);
        free(okm);
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_EXPAND_FAILED,
                              "Failed to create HKDF context");
        logOpenSSLError("EVP_KDF_CTX_new");
        logFunctionExit(functionName);
        return NULL;
    }

    // Set up parameters for expand
    OSSL_PARAM params[5] = {0};
    int        mode      = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char*)algoName, 0);
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, prkBytes, prkLen);

    if (infoBytes != NULL && infoLen > 0) {
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                      infoBytes, infoLen);
        params[4] = OSSL_PARAM_construct_end();
    } else {
        params[3] = OSSL_PARAM_construct_end();
    }

    // Perform expand
    int result = EVP_KDF_derive(kctx, okm, length, params);

    // Clean up contexts
    EVP_KDF_CTX_free(kctx);
    EVP_MD_free(md);

    if (result != 1) {
        // Clean up on error
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        free(okm);
        setPendingOpenSSLException(env, OPENSSL_HKDF_EXPAND_FAILED,
                              "HKDF expand failed");
        logOpenSSLError("EVP_KDF_derive");
        logFunctionExit(functionName);
        return NULL;
    }

    // Clean up after successful derivation
    if (infoBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
    }
    (*env)->ReleaseByteArrayElements(env, prk, prkBytes, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF Expanded OKM:");
        gslogMessageHex((char*)okm, 0, length, 0, 0, NULL);
    }
#endif

    // Create Java byte array for result
    jbyteArray result_array =
        newByteArraySafe(env, length, "Failed to create result array");
    if (result_array == NULL) {
        free(okm);
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                              "Failed to create result array");
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result_array, 0, length, (jbyte*)okm);
    free(okm);

    logFunctionExit(functionName);

    return result_array;
}

//============================================================================
// HKDF_derive - Combined extract and expand in one operation
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_HKDF_1derive(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo, jbyteArray salt,
    jbyteArray ikm, jbyteArray info, jint length) {
    static const char* functionName = "OpenSSLNativeInterface.HKDF_derive";

    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        if (debug) {
            gslogMessage("DETAIL_HKDF FAILURE: Failed to get OpenSSL context");
        }
        logFunctionExit(functionName);
        return NULL;
    }

    // Get digest algorithm name
    const char* algoName = getStringUTFCharsSafe(
        env, digestAlgo, functionName, "Digest algorithm name is NULL");
    if (algoName == NULL) {
        return NULL;
    }

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF Derive - Algorithm: %s, Length: %d", algoName,
                     length);
    }
#endif

    // Get salt bytes (can be NULL)
    jbyte* saltBytes = NULL;
    jsize  saltLen   = 0;
    if (salt != NULL) {
        saltBytes = getByteArrayElementsSafe(env, salt, functionName, "salt");
        if (saltBytes == NULL) {
            cleanupStringUTFChars(env, digestAlgo, algoName);
            return NULL;
        }
        saltLen = (*env)->GetArrayLength(env, salt);
    }

    // Get IKM bytes
    jbyte* ikmBytes = getByteArrayElementsSafe(env, ikm, functionName, "IKM is NULL");
    if (ikmBytes == NULL) {
        if (saltBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
        }
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        logFunctionExit(functionName);
        return NULL;
    }
    jsize ikmLen = (*env)->GetArrayLength(env, ikm);

    // Get info bytes (can be NULL)
    jbyte* infoBytes = NULL;
    jsize  infoLen   = 0;
    if (info != NULL) {
        infoBytes = getByteArrayElementsSafe(env, info, functionName, "info");
        if (infoBytes == NULL) {
            if (saltBytes != NULL) {
                (*env)->ReleaseByteArrayElements(env, salt, saltBytes,
                                                 JNI_ABORT);
            }
            (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
            (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
            logFunctionExit(functionName);
            return NULL;
        }
        infoLen = (*env)->GetArrayLength(env, info);
    }

    // Allocate output buffer (already zeroed by mallocSafe)
    unsigned char* okm = (unsigned char*)mallocSafe(
        env, length, "Failed to allocate memory for OKM");
    if (okm == NULL) {
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
        }
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                              "Failed to allocate memory for OKM");
        logFunctionExit(functionName);
        return NULL;
    }

    // Fetch the digest using library context
    EVP_MD* md = EVP_MD_fetch(context->libctx, algoName, NULL);
    if (md == NULL) {
        free(okm);
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
        }
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_DERIVE_FAILED,
                              "Failed to fetch digest algorithm");
        logOpenSSLError("EVP_MD_fetch");
        logFunctionExit(functionName);
        return NULL;
    }

    // Create KDF context
    EVP_KDF* kdf = EVP_KDF_fetch(context->libctx, "HKDF", NULL);
    if (kdf == NULL) {
        EVP_MD_free(md);
        free(okm);
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
        }
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_DERIVE_FAILED,
                              "Failed to fetch HKDF");
        logOpenSSLError("EVP_KDF_fetch");
        logFunctionExit(functionName);
        return NULL;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (kctx == NULL) {
        EVP_MD_free(md);
        free(okm);
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
        }
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        setPendingOpenSSLException(env, OPENSSL_HKDF_DERIVE_FAILED,
                              "Failed to create HKDF context");
        logOpenSSLError("EVP_KDF_CTX_new");
        logFunctionExit(functionName);
        return NULL;
    }

    // Set up parameters for combined extract and expand
    OSSL_PARAM params[6] = {0};
    int        mode      = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    int        paramIdx  = 0;

    params[paramIdx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[paramIdx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                          (char*)algoName, 0);
    params[paramIdx++] =
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikmBytes, ikmLen);

    if (saltBytes != NULL && saltLen > 0) {
        params[paramIdx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, saltBytes, saltLen);
    }

    if (infoBytes != NULL && infoLen > 0) {
        params[paramIdx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, infoBytes, infoLen);
    }

    params[paramIdx] = OSSL_PARAM_construct_end();

    // Perform derive
    int result = EVP_KDF_derive(kctx, okm, length, params);

    // Clean up contexts
    EVP_KDF_CTX_free(kctx);
    EVP_MD_free(md);

    if (result != 1) {
        // Clean up on error
        if (infoBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
        if (saltBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
        }
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);
        free(okm);
        setPendingOpenSSLException(env, OPENSSL_HKDF_DERIVE_FAILED,
                              "HKDF derive failed");
        logOpenSSLError("EVP_KDF_derive");
        logFunctionExit(functionName);
        return NULL;
    }

    // Clean up after successful derivation
    if (infoBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, info, infoBytes, JNI_ABORT);
    }
    (*env)->ReleaseByteArrayElements(env, ikm, ikmBytes, JNI_ABORT);
    if (saltBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, salt, saltBytes, JNI_ABORT);
    }
    (*env)->ReleaseStringUTFChars(env, digestAlgo, algoName);

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF Derived OKM:");
        gslogMessageHex((char*)okm, 0, length, 0, 0, NULL);
    }
#endif

    // Create Java byte array for result
    jbyteArray result_array =
        newByteArraySafe(env, length, "Failed to create result array");
    if (result_array == NULL) {
        free(okm);
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                              "Failed to create result array");
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result_array, 0, length, (jbyte*)okm);
    free(okm);

    logFunctionExit(functionName);

    return result_array;
}
