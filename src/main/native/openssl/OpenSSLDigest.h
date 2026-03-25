/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLDigest.h
 * @brief Cryptographic hash/digest operations using OpenSSL.
 *
 * This header defines the interface for message digest (hash) operations.
 * It supports various hash algorithms including:
 * - SHA-1 (legacy, not recommended for new applications)
 * - SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512
 * - SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512
 *
 * The implementation uses OpenSSL's EVP interface for algorithm-independent
 * digest operations with support for streaming, context cloning, and reuse.
 */

#ifndef _OPENSSL_DIGEST_H
#define _OPENSSL_DIGEST_H

#include <jni.h>
#include <openssl/evp.h>
#include "OpenSSLContext.h"

/**
 * Structure to hold OpenSSL digest context information.
 * This structure maintains the state for digest operations.
 */
typedef struct {
    EVP_MD_CTX*   mdCtx;      // OpenSSL message digest context
    const EVP_MD* md;         // Message digest algorithm
    int           digestSize; // Size of the digest output in bytes
} OpenSSLDigestContext;

/**
 * Create a new digest context for the specified algorithm.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param digestAlgo Name of the digest algorithm (e.g., "SHA-256", "SHA3-512")
 * @return Digest context ID (pointer cast to jlong), or 0 on failure
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1create(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo);

/**
 * Create a copy of an existing digest context.
 * This allows branching digest computations at intermediate states.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Source digest context ID
 * @return New digest context ID (copy), or 0 on failure
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1copy(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId);

/**
 * Update the digest with additional data.
 * Can be called multiple times to process data in chunks.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID
 * @param data Input data to hash
 * @param offset Offset in the data array
 * @param dataLen Length of data to process
 * @return 1 on success, negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1update(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId, jbyteArray data,
    jint offset, jint dataLen);

/**
 * Finalize the digest and return the hash value.
 * After calling this, the digest context is automatically reset.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID
 * @return Byte array containing the digest hash
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1digest(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId);

/**
 * Finalize the digest, store result in provided array, and reset for reuse.
 * This is more efficient than digest() when the output buffer is pre-allocated.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID
 * @param output Output array to store the digest
 * @return 1 on success, negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1digest_1and_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId, jbyteArray output);

/**
 * Get the size of the digest output in bytes.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID
 * @return Size of digest in bytes, or negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1size(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId);

/**
 * Reset the digest context to its initial state.
 * Allows reusing the same context for a new digest computation.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId);

/**
 * Delete the digest context and free associated resources.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID to delete
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_DIGEST_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong digestId);

/**
 * Internal helper function to validate digest context.
 * Centralizes validation logic used by all digest operations.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param digestId Digest context ID
 * @param functionName Name of calling function (for logging)
 * @param digestCtx Output parameter for validated digest context
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateDigestContext(JNIEnv* env, jint fipsFlag, jlong digestId,
                         const char* functionName,
                         OpenSSLDigestContext** digestCtx);

#endif 


