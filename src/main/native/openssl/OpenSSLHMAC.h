/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHMAC.h
 * @brief HMAC (Hash-based Message Authentication Code) operations using OpenSSL.
 *
 * This header defines the interface for HMAC operations. HMAC provides
 * message authentication using a cryptographic hash function combined
 * with a secret key.
 *
 * Supported hash algorithms:
 * - SHA-1 (legacy, not recommended for new applications)
 * - SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512
 * - SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512
 *
 * HMAC is specified in RFC 2104 and FIPS 198-1. The implementation uses
 * OpenSSL's HMAC interface with support for streaming operations and
 * context reuse.
 */

#ifndef _OPENSSL_HMAC_H
#define _OPENSSL_HMAC_H

#include <jni.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "OpenSSLContext.h"

/**
 * Structure to hold OpenSSL HMAC context information.
 * This structure maintains the state for HMAC operations.
 */
typedef struct {
    HMAC_CTX*     hmacCtx;    // OpenSSL HMAC context
    const EVP_MD* md;         // Message digest algorithm (e.g., SHA-256)
    int           macSize;    // Size of the MAC output in bytes
} OpenSSLHMACContext;

/**
 * Create a new HMAC context for the specified digest algorithm.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param digestAlgo Name of the digest algorithm (e.g., "SHA-256", "SHA-512")
 * @return HMAC context ID (pointer cast to jlong), or 0 on failure
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1create(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo);

/**
 * Initialize HMAC context with a secret key.
 * Must be called before update operations.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID
 * @param key Secret key for HMAC
 * @param keyLen Length of the key
 * @return 1 on success, negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1init(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId, jbyteArray key,
    jint keyLen);

/**
 * Update the HMAC with additional data.
 * Can be called multiple times to process data in chunks.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID
 * @param data Input data to process
 * @param offset Offset in the data array
 * @param dataLen Length of data to process
 * @return 1 on success, negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1update(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId, jbyteArray data,
    jint offset, jint dataLen);

/**
 * Finalize the HMAC, store result in provided array, and reset for reuse.
 * This matches the OCK pattern and OpenSSL's native API design.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID
 * @param output Pre-allocated output array to store the HMAC (must be at least macSize bytes)
 * @return 1 on success, -1 on failure (with exception thrown)
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1doFinal(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId, jbyteArray output);

/**
 * Get the size of the HMAC output in bytes.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID
 * @return Size of HMAC in bytes, or negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1size(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId);

/**
 * Reset the HMAC context to its initial state.
 * Allows reusing the same context for a new HMAC computation.
 * Note: The key must be re-initialized with HMAC_init after reset.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId);

/**
 * Delete the HMAC context and free associated resources.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID to delete
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HMAC_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong hmacId);

/**
 * Internal helper function to validate HMAC context.
 * Centralizes validation logic used by all HMAC operations.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param hmacId HMAC context ID
 * @param functionName Name of calling function (for logging)
 * @param hmacCtx Output parameter for validated HMAC context
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateHMACContext(JNIEnv* env, jint fipsFlag, jlong hmacId,
                       const char* functionName,
                       OpenSSLHMACContext** hmacCtx);

#endif 


