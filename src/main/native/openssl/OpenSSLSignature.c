/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLSignature.c
 * @brief Implementation of digital signature operations using OpenSSL.
 *
 * This file implements digital signature operations using OpenSSL's EVP
 * interface. It supports various signature algorithms including RSA, ECDSA,
 * EdDSA, DSA, and RSA-PSS.
 *
 * Key features:
 * - Multiple signature algorithm support via EVP interface
 * - Streaming signature operations (update multiple times)
 * - Support for both signing (private key) and verification (public key)
 * - RSA-PSS parameter configuration
 * - Efficient memory management with context reuse
 * - FIPS mode support
 *
 * The implementation uses OpenSSL 3.0+ EVP_PKEY API with proper context
 * management and reference counting to prevent memory leaks.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>

/* Signature context struct and constants (formerly in OpenSSLSignature.h) */
#define SIGNATURE_MODE_SIGN   1
#define SIGNATURE_MODE_VERIFY 2

typedef struct {
    EVP_MD_CTX*    mdCtx;
    EVP_PKEY*      pkey;
    const EVP_MD*  md;
    int            mode;
    int            signatureSize;
    EVP_PKEY_CTX*  pkeyCtx;
    int            isEdDSA;
    unsigned char* dataBuffer;
    size_t         dataBufferSize;
    size_t         dataBufferCapacity;
} OpenSSLSignatureContext;

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

//============================================================================
// Helper function to validate signature context
//============================================================================
int validateSignatureContext(JNIEnv* env, jint fipsFlag, jlong signatureId,
                              const char* functionName,
                              OpenSSLSignatureContext** signatureCtx) {
    logFunctionEntry(functionName);

    // Validate FIPS flag
    if (!validateAndGetContext(env, fipsFlag, functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Validate signature context pointer
    OpenSSLSignatureContext* ctx = (OpenSSLSignatureContext*)((intptr_t)signatureId);
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_NULL,
                                   "Signature context is NULL");
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE OpenSSL Signature context is NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    // Validate internal structures
    if (ctx->mdCtx == NULL || ctx->pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "Signature context is invalid");
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE FAILURE: Signature context structures are NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    *signatureCtx = ctx;
    return 1;
}

//============================================================================
// Helper function to load key from bytes
//============================================================================
static EVP_PKEY* loadKeyFromBytes(JNIEnv* env, OpenSSLContext* context,
                                   jbyteArray keyBytes, int isPrivateKey,
                                   const char* functionName) {
    // Get key bytes
    jbyte* keyData = getByteArrayElementsSafe(env, keyBytes, functionName,
                                              "Failed to get key bytes");
    if (keyData == NULL) {
        return NULL;
    }

    jsize keyLen = (*env)->GetArrayLength(env, keyBytes);
    
    // Create BIO from key bytes
    BIO* bio = BIO_new_mem_buf(keyData, keyLen);
    if (bio == NULL) {
        cleanupByteArray(env, keyBytes, keyData, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_KEY_LOAD_FAILED,
                                   "Failed to create BIO for key");
        logOpenSSLError("BIO_new_mem_buf");
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    if (isPrivateKey) {
        // Load private key (PKCS#8 format)
        pkey = d2i_PrivateKey_bio(bio, NULL);
        if (pkey == NULL) {
            BIO_free(bio);
            cleanupByteArray(env, keyBytes, keyData, JNI_ABORT);
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_KEY_LOAD_FAILED,
                                       "Failed to load private key");
            logOpenSSLError("d2i_PrivateKey_bio");
            return NULL;
        }
    } else {
        // Load public key (X.509 SubjectPublicKeyInfo format)
        pkey = d2i_PUBKEY_bio(bio, NULL);
        if (pkey == NULL) {
            BIO_free(bio);
            cleanupByteArray(env, keyBytes, keyData, JNI_ABORT);
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_KEY_LOAD_FAILED,
                                       "Failed to load public key");
            logOpenSSLError("d2i_PUBKEY_bio");
            return NULL;
        }
    }

    BIO_free(bio);
    cleanupByteArray(env, keyBytes, keyData, JNI_ABORT);

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Loaded %s key, type: %d",
                     isPrivateKey ? "private" : "public",
                     EVP_PKEY_get_id(pkey));
    }
#endif

    return pkey;
}

//============================================================================
// SIGNATURE_create - Create a new signature context
//============================================================================
static jlong signature_create_impl(JNIEnv* env, jclass cls, jint fipsFlag, jbyteArray keyBytes,
    jint keyLength, jstring algorithm, jint mode) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_create";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Get algorithm name
    const char* algoName = getStringUTFCharsSafe(env, algorithm, functionName,
                                                 "Signature algorithm name is NULL");
    if (algoName == NULL) {
        return 0;
    }

    // Determine if this is a signing or verification operation
    // mode: 0 = sign (needs private key), 1 = verify (needs public key)
    jint isPrivateKey = (mode == 0) ? 1 : 0;
    
    // Parse algorithm string to extract digest and key type
    // Supports formats like:
    // - "SHA256withRSA", "SHA256withECDSA", "SHA256withDSA"
    // - "NONEwithECDSA", "NONEwithRSA" (pre-computed digest)
    // - "SHA256" (digest only, for direct use)
    // - "Ed25519", "Ed448" (EdDSA, no digest needed)
    const char* digestName = NULL;
    char digestBuffer[64] = {0};
    
    // Check if this is EdDSA (no digest needed)
    if (strstr(algoName, "Ed25519") != NULL || strstr(algoName, "Ed448") != NULL) {
        digestName = NULL;  // EdDSA doesn't use a separate digest
    }
    // Parse "DigestwithKeyType" format
    else if (strstr(algoName, "with") != NULL) {
        const char* withPos = strstr(algoName, "with");
        size_t digestLen = withPos - algoName;
        if (digestLen > 0 && digestLen < sizeof(digestBuffer)) {
            strncpy(digestBuffer, algoName, digestLen);
            digestBuffer[digestLen] = '\0';
            // Check if digest is "NONE" - means pre-computed digest, no hashing
            if (strcmp(digestBuffer, "NONE") == 0 || strcmp(digestBuffer, "None") == 0) {
                digestName = NULL;  // No digest algorithm, data is already hashed
            } else {
                digestName = digestBuffer;
            }
        }
    }
    // Otherwise, treat the entire string as the digest name
    else {
        digestName = algoName;
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Creating signature for algorithm: %s, digest: %s, FIPS: %d, mode: %s",
                     algoName, digestName ? digestName : "none", fipsFlag,
                     isPrivateKey ? "sign" : "verify");
    }
#endif

    // Allocate signature context structure
    OpenSSLSignatureContext* signatureCtx = (OpenSSLSignatureContext*)mallocSafe(
        env, sizeof(OpenSSLSignatureContext), "Failed to allocate signature context");
    if (signatureCtx == NULL) {
        cleanupStringUTFChars(env, algorithm, algoName);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize all fields to zero/NULL
    memset(signatureCtx, 0, sizeof(OpenSSLSignatureContext));
    
    // Set mode
    signatureCtx->mode = isPrivateKey ? SIGNATURE_MODE_SIGN : SIGNATURE_MODE_VERIFY;
    
    // Detect if this is EdDSA (requires one-shot API instead of streaming)
    signatureCtx->isEdDSA = (strstr(algoName, "Ed25519") != NULL || strstr(algoName, "Ed448") != NULL) ? 1 : 0;
    
    // Initialize EdDSA buffer if needed
    if (signatureCtx->isEdDSA) {
        signatureCtx->dataBufferCapacity = 4096;  // Initial buffer size
        signatureCtx->dataBuffer = (unsigned char*)malloc(signatureCtx->dataBufferCapacity);
        if (signatureCtx->dataBuffer == NULL) {
            free(signatureCtx);
            cleanupStringUTFChars(env, algorithm, algoName);
            setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                       "Failed to allocate EdDSA data buffer");
            logFunctionExit(functionName);
            return 0;
        }
        signatureCtx->dataBufferSize = 0;
        
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE EdDSA detected, using buffered one-shot API");
        }
    }

    // Load key
    signatureCtx->pkey = loadKeyFromBytes(env, context, keyBytes, isPrivateKey, functionName);
    if (signatureCtx->pkey == NULL) {
        if (signatureCtx->dataBuffer != NULL) {
            free(signatureCtx->dataBuffer);
        }
        free(signatureCtx);
        cleanupStringUTFChars(env, algorithm, algoName);
        return 0;
    }

    // Fetch digest algorithm if provided (not needed for EdDSA)
    if (digestName != NULL && strlen(digestName) > 0) {
        signatureCtx->md = fetchDigestSafe(env, context, digestName, functionName,
                                          OPENSSL_SIGNATURE_ALGORITHM_NOT_FOUND,
                                          "Failed to fetch digest algorithm");
        if (signatureCtx->md == NULL) {
            if (signatureCtx->dataBuffer != NULL) free(signatureCtx->dataBuffer);
            EVP_PKEY_free(signatureCtx->pkey);
            free(signatureCtx);
            cleanupStringUTFChars(env, algorithm, algoName);
            return 0;
        }
    } else {
        signatureCtx->md = NULL;
    }

    // Create message digest context
    signatureCtx->mdCtx = createMDCtxSafe(env, functionName,
                                         OPENSSL_SIGNATURE_CTX_NEW_FAILED,
                                         "Failed to create signature context");
    if (signatureCtx->mdCtx == NULL) {
        if (signatureCtx->md) EVP_MD_free((EVP_MD*)signatureCtx->md);
        if (signatureCtx->dataBuffer != NULL) free(signatureCtx->dataBuffer);
        EVP_PKEY_free(signatureCtx->pkey);
        free(signatureCtx);
        cleanupStringUTFChars(env, algorithm, algoName);
        return 0;
    }

    // Initialize signature operation
    // Use the old API with the fetched MD object (not _ex version)
    int result;
    if (isPrivateKey) {
        result = EVP_DigestSignInit(signatureCtx->mdCtx, &signatureCtx->pkeyCtx,
                                    signatureCtx->md, NULL, signatureCtx->pkey);
    } else {
        result = EVP_DigestVerifyInit(signatureCtx->mdCtx, &signatureCtx->pkeyCtx,
                                      signatureCtx->md, NULL, signatureCtx->pkey);
    }

    if (result != 1) {
        EVP_MD_CTX_free(signatureCtx->mdCtx);
        if (signatureCtx->md) EVP_MD_free((EVP_MD*)signatureCtx->md);
        if (signatureCtx->dataBuffer != NULL) free(signatureCtx->dataBuffer);
        EVP_PKEY_free(signatureCtx->pkey);
        free(signatureCtx);
        cleanupStringUTFChars(env, algorithm, algoName);
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INIT_FAILED,
                                   "Failed to initialize signature operation");
        logOpenSSLError(isPrivateKey ? "EVP_DigestSignInit_ex" : "EVP_DigestVerifyInit_ex");
        logFunctionExit(functionName);
        return 0;
    }

    // Get signature size
    // For ECDSA and other algorithms, EVP_PKEY_get_size gives the maximum signature size
    // We don't call EVP_DigestSign with NULL here as it can interfere with context state
    signatureCtx->signatureSize = EVP_PKEY_get_size(signatureCtx->pkey);

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Created signature context: %p, size: %d bytes",
                     signatureCtx, signatureCtx->signatureSize);
    }
#endif

    cleanupStringUTFChars(env, algorithm, algoName);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)signatureCtx);
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1create(
    JNIEnv* env, jclass cls, jint fipsFlag, jbyteArray keyBytes,
    jint keyLength, jstring algorithm, jint mode) {
    return signature_create_impl(env, cls, fipsFlag, keyBytes, keyLength, algorithm, mode);
}

//============================================================================
// SIGNATURE_update - Update signature with data
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1update(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId,
    jbyteArray data, jint offset, jint dataLen) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_update";

    OpenSSLSignatureContext* signatureCtx = NULL;
    if (!validateSignatureContext(env, fipsFlag, signatureId, functionName,
                                   &signatureCtx)) {
        return -1;
    }

    // Validate input
    if (data == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "Input data is NULL");
        logFunctionExit(functionName);
        return -1;
    }

    if (dataLen == 0) {
        logFunctionExit(functionName);
        return 1;  // Nothing to update
    }

    jsize arrayLen = (*env)->GetArrayLength(env, data);
    if (!validateOffsetAndLength(env, arrayLen, offset, dataLen, functionName,
                                 "Invalid data offset/length")) {
        return -1;
    }

    // Get data array
    jbyte* dataBytes = getByteArrayElementsSafe(env, data, functionName,
                                               "Failed to get data array");
    if (dataBytes == NULL) {
        return -1;
    }

#ifdef DEBUG_SIGNATURE_DATA
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Updating signature with %d bytes at offset %d",
                     dataLen, offset);
        gslogMessageHex((char*)(dataBytes + offset), 0, dataLen, 0, 0, NULL);
    }
#endif

    // For EdDSA, buffer the data instead of using streaming API
    if (signatureCtx->isEdDSA) {
        // Check if we need to grow the buffer
        size_t requiredSize = signatureCtx->dataBufferSize + (size_t)dataLen;
        if (requiredSize > signatureCtx->dataBufferCapacity) {
            // Grow buffer (double it or add required size, whichever is larger)
            size_t newCapacity = signatureCtx->dataBufferCapacity * 2;
            if (newCapacity < requiredSize) {
                newCapacity = requiredSize;
            }
            
            unsigned char* newBuffer = (unsigned char*)realloc(signatureCtx->dataBuffer, newCapacity);
            if (newBuffer == NULL) {
                cleanupByteArray(env, data, dataBytes, JNI_ABORT);
                setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                           "Failed to grow EdDSA data buffer");
                logFunctionExit(functionName);
                return -1;
            }
            
            signatureCtx->dataBuffer = newBuffer;
            signatureCtx->dataBufferCapacity = newCapacity;
            
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE EdDSA buffer grown to %zu bytes", newCapacity);
            }
        }
        
        // Copy data to buffer
        memcpy(signatureCtx->dataBuffer + signatureCtx->dataBufferSize,
               dataBytes + offset, (size_t)dataLen);
        signatureCtx->dataBufferSize += (size_t)dataLen;
        
        cleanupByteArray(env, data, dataBytes, JNI_ABORT);
        
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE EdDSA buffered %d bytes, total: %zu bytes",
                         dataLen, signatureCtx->dataBufferSize);
        }
    } else {
        // For non-EdDSA algorithms, use streaming API
        int result;
        if (signatureCtx->mode == SIGNATURE_MODE_SIGN) {
            result = EVP_DigestSignUpdate(signatureCtx->mdCtx,
                                          (unsigned char*)(dataBytes + offset),
                                          (size_t)dataLen);
        } else {
            result = EVP_DigestVerifyUpdate(signatureCtx->mdCtx,
                                            (unsigned char*)(dataBytes + offset),
                                            (size_t)dataLen);
        }

        cleanupByteArray(env, data, dataBytes, JNI_ABORT);

        if (result != 1) {
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_UPDATE_FAILED,
                                       "Failed to update signature");
            logOpenSSLError(signatureCtx->mode == SIGNATURE_MODE_SIGN ?
                           "EVP_DigestSignUpdate" : "EVP_DigestVerifyUpdate");
            logFunctionExit(functionName);
            return -1;
        }
    }

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// SIGNATURE_sign - Finalize signature and return signature bytes
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1sign(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_sign";

    OpenSSLSignatureContext* signatureCtx = NULL;
    if (!validateSignatureContext(env, fipsFlag, signatureId, functionName,
                                   &signatureCtx)) {
        return NULL;
    }

    // Verify this is a signing context
    if (signatureCtx->mode != SIGNATURE_MODE_SIGN) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "Cannot sign with verification context");
        logFunctionExit(functionName);
        return NULL;
    }

    // Get signature length
    // Use the pre-calculated signature size to avoid interfering with context state
    // Calling EVP_DigestSignFinal with NULL can cause issues with ECDSA and other algorithms
    size_t sigLen = (size_t)signatureCtx->signatureSize;
    
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE SIGN: Starting sign operation, max size: %zu", sigLen);
    }
    
    // Clear any pending OpenSSL errors before we start
    ERR_clear_error();

    // Allocate a C buffer for the signature (not a Java array yet)
    unsigned char* signatureBuffer = (unsigned char*)malloc(sigLen);
    if (signatureBuffer == NULL) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE SIGN: Failed to allocate buffer");
        }
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "Failed to allocate signature buffer");
        logFunctionExit(functionName);
        return NULL;
    }

    // For EdDSA, use one-shot API with buffered data
    int result;
    if (signatureCtx->isEdDSA) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE SIGN: EdDSA one-shot sign with %zu bytes",
                         signatureCtx->dataBufferSize);
        }
        
        // Use EVP_DigestSign for one-shot signing
        result = EVP_DigestSign(signatureCtx->mdCtx, signatureBuffer, &sigLen,
                                signatureCtx->dataBuffer, signatureCtx->dataBufferSize);
        
        if (result != 1) {
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE SIGN: EVP_DigestSign FAILED, result=%d", result);
            }
            free(signatureBuffer);
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_SIGN_FAILED,
                                       "Failed to sign with EdDSA");
            logOpenSSLError("EVP_DigestSign");
            logFunctionExit(functionName);
            return NULL;
        }
    } else {
        // For non-EdDSA, use streaming API finalization
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE SIGN: Calling EVP_DigestSignFinal");
        }
        result = EVP_DigestSignFinal(signatureCtx->mdCtx, signatureBuffer, &sigLen);

        if (result != 1) {
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE SIGN: EVP_DigestSignFinal FAILED, result=%d", result);
            }
            free(signatureBuffer);
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_SIGN_FAILED,
                                       "Failed to finalize signature");
            logOpenSSLError("EVP_DigestSignFinal");
            logFunctionExit(functionName);
            return NULL;
        }
    }
    
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE SIGN: EVP_DigestSignFinal SUCCESS, actual size: %zu", sigLen);
    }
    
    // Clear OpenSSL error queue after successful operation
    ERR_clear_error();

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Finalized signature, size: %zu bytes", sigLen);
        gslogMessageHex((char*)signatureBuffer, 0, (int)sigLen, 0, 0, NULL);
    }
#endif

    // Now create a Java byte array with the actual signature size
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE SIGN: Creating Java array, size: %zu", sigLen);
    }
    jbyteArray signatureBytes = (*env)->NewByteArray(env, (jsize)sigLen);
    if (signatureBytes == NULL || (*env)->ExceptionCheck(env)) {
        // NewByteArray returns NULL and sets OutOfMemoryError if allocation fails
        // Don't call setPendingOpenSSLException - there's already a pending exception!
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE SIGN: Failed to create Java array (exception already pending)");
        }
        free(signatureBuffer);
        logFunctionExit(functionName);
        return NULL;
    }

    // Copy signature data from C buffer to Java array
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE SIGN: Copying to Java array");
    }
    (*env)->SetByteArrayRegion(env, signatureBytes, 0, (jsize)sigLen, (jbyte*)signatureBuffer);
    
    // Free the C buffer
    free(signatureBuffer);
    
    // Check if SetByteArrayRegion threw an exception
    // Check if SetByteArrayRegion threw an exception
    if ((*env)->ExceptionCheck(env)) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE SIGN: SetByteArrayRegion threw exception!");
        }
        logFunctionExit(functionName);
        return NULL;
    }
    
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE SIGN: SUCCESS - returning signature");
    }

    // Note: We don't reset the context here as it will be deleted or reused by the caller
    // Resetting after sign/verify can cause issues with subsequent operations

    logFunctionExit(functionName);
    return signatureBytes;
}

//============================================================================
// SIGNATURE_verify - Verify signature
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1verify(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId,
    jbyteArray signature) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_verify";
    
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE VERIFY: Starting verify operation");
    }
    

    OpenSSLSignatureContext* signatureCtx = NULL;
    if (!validateSignatureContext(env, fipsFlag, signatureId, functionName,
                                   &signatureCtx)) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE VERIFY: Context validation failed");
        }
        return -1;
    }

    // Verify this is a verification context
    if (signatureCtx->mode != SIGNATURE_MODE_VERIFY) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE VERIFY: Wrong mode");
        }
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "Cannot verify with signing context");
        logFunctionExit(functionName);
        return -1;
    }

    // Validate signature array
    if (signature == NULL) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE VERIFY: Signature is NULL");
        }
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "Signature array is NULL");
        logFunctionExit(functionName);
        return -1;
    }

    jsize sigLen = (*env)->GetArrayLength(env, signature);
    if (sigLen <= 0) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE VERIFY: Signature is empty");
        }
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "Signature array is empty");
        logFunctionExit(functionName);
        return -1;
    }
    
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE VERIFY: Signature length: %d", sigLen);
    }

    // Get signature bytes
    jbyte* sigBytes = getByteArrayElementsSafe(env, signature, functionName,
                                              "Failed to get signature bytes");
    if (sigBytes == NULL) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE VERIFY: Failed to get signature bytes");
        }
        return -1;
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Verifying signature, size: %d bytes", sigLen);
        gslogMessageHex((char*)sigBytes, 0, sigLen, 0, 0, NULL);
    }
#endif

    // For EdDSA, use one-shot API with buffered data
    int result;
    if (signatureCtx->isEdDSA) {
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE VERIFY: EdDSA one-shot verify with %zu bytes",
                         signatureCtx->dataBufferSize);
        }
        
        // Use EVP_DigestVerify for one-shot verification
        result = EVP_DigestVerify(signatureCtx->mdCtx, (unsigned char*)sigBytes, (size_t)sigLen,
                                  signatureCtx->dataBuffer, signatureCtx->dataBufferSize);
    } else {
        // For non-EdDSA, use streaming API finalization
        result = EVP_DigestVerifyFinal(signatureCtx->mdCtx,
                                       (unsigned char*)sigBytes, (size_t)sigLen);
    }

    cleanupByteArray(env, signature, sigBytes, JNI_ABORT);

    // Note: We don't reset the context here as it will be deleted or reused by the caller
    // Resetting after sign/verify can cause issues with subsequent operations

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Verification result: %s",
                     result == 1 ? "VALID" : "INVALID");
    }
#endif

    logFunctionExit(functionName);
    
    // Return 1 for valid, 0 for invalid, -1 for error
    if (result == 1) {
        return 1;  // Valid signature
    } else if (result == 0) {
        return 0;  // Invalid signature (not an error)
    } else {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_VERIFY_FAILED,
                                   "Failed to verify signature");
        logOpenSSLError("EVP_DigestVerifyFinal");
        return -1;  // Error
    }
}

//============================================================================
// SIGNATURE_size - Get signature size
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1size(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_size";

    OpenSSLSignatureContext* signatureCtx = NULL;
    if (!validateSignatureContext(env, fipsFlag, signatureId, functionName,
                                   &signatureCtx)) {
        return -1;
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Signature size: %d bytes",
                     signatureCtx->signatureSize);
    }
#endif

    logFunctionExit(functionName);
    return signatureCtx->signatureSize;
}

//============================================================================
// SIGNATURE_reset - Reset signature to initial state
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_reset";

    OpenSSLSignatureContext* signatureCtx = NULL;
    if (!validateSignatureContext(env, fipsFlag, signatureId, functionName,
                                   &signatureCtx)) {
        return;
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Resetting signature context: %p", signatureCtx);
    }
#endif

    // For EdDSA, clear the data buffer
    if (signatureCtx->isEdDSA && signatureCtx->dataBuffer != NULL) {
        signatureCtx->dataBufferSize = 0;
    }

    /* Re-initialise using the same EVP_MD that was stored at create time.
     * Passing NULL as the mdname would silently fail for non-EdDSA algorithms
     * (RSA, ECDSA, DSA) that require a digest; the stored signatureCtx->md
     * pointer is still valid and must be re-supplied. */
    int result;
    if (signatureCtx->mode == SIGNATURE_MODE_SIGN) {
        result = EVP_DigestSignInit(signatureCtx->mdCtx, &signatureCtx->pkeyCtx,
                                    signatureCtx->md, NULL, signatureCtx->pkey);
        if (result != 1) {
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INIT_FAILED,
                                       "Failed to reset signature");
            logOpenSSLError("EVP_DigestSignInit");
        }
    } else {
        result = EVP_DigestVerifyInit(signatureCtx->mdCtx, &signatureCtx->pkeyCtx,
                                      signatureCtx->md, NULL, signatureCtx->pkey);
        if (result != 1) {
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INIT_FAILED,
                                       "Failed to reset signature");
            logOpenSSLError("EVP_DigestVerifyInit");
        }
    }

    logFunctionExit(functionName);
}

//============================================================================
// SIGNATURE_setPSSParams - Set RSA-PSS parameters
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1setPSSParams(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId,
    jint saltLen, jstring mgf1Digest) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_setPSSParams";

    OpenSSLSignatureContext* signatureCtx = NULL;
    if (!validateSignatureContext(env, fipsFlag, signatureId, functionName,
                                   &signatureCtx)) {
        return -1;
    }

    // Verify we have a pkey context
    if (signatureCtx->pkeyCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "No key context available for PSS parameters");
        logFunctionExit(functionName);
        return -1;
    }

    // Set RSA padding to PSS
    if (EVP_PKEY_CTX_set_rsa_padding(signatureCtx->pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                   "Failed to set RSA PSS padding");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_padding");
        logFunctionExit(functionName);
        return -1;
    }

    // Set salt length
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(signatureCtx->pkeyCtx, saltLen) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                   "Failed to set PSS salt length");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        logFunctionExit(functionName);
        return -1;
    }

    // Set MGF1 digest if provided
    if (mgf1Digest != NULL) {
        const char* mgf1Name = getStringUTFCharsSafe(env, mgf1Digest, functionName,
                                                     "MGF1 digest name is NULL");
        if (mgf1Name == NULL) {
            return -1;
        }

        // Must use the context-aware library context so that FIPS mode is respected.
        OpenSSLContext* context = NULL;
        if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
            cleanupStringUTFChars(env, mgf1Digest, mgf1Name);
            return -1;
        }
        const EVP_MD* mgf1Md = EVP_MD_fetch(context->libctx, mgf1Name, NULL);
        if (mgf1Md == NULL) {
            cleanupStringUTFChars(env, mgf1Digest, mgf1Name);
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                       "Failed to fetch MGF1 digest");
            logOpenSSLError("EVP_MD_fetch");
            logFunctionExit(functionName);
            return -1;
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(signatureCtx->pkeyCtx, mgf1Md) <= 0) {
            EVP_MD_free((EVP_MD*)mgf1Md);
            cleanupStringUTFChars(env, mgf1Digest, mgf1Name);
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                       "Failed to set MGF1 digest");
            logOpenSSLError("EVP_PKEY_CTX_set_rsa_mgf1_md");
            logFunctionExit(functionName);
            return -1;
        }

        EVP_MD_free((EVP_MD*)mgf1Md);
        cleanupStringUTFChars(env, mgf1Digest, mgf1Name);
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Set PSS parameters: saltLen=%d", saltLen);
    }
#endif

    logFunctionExit(functionName);
    return 1;
}

//============================================================================
// SIGNATURE_delete - Delete signature context and free resources
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId) {
    static const char* functionName = "OpenSSLNativeInterface.SIGNATURE_delete";
    logFunctionEntry(functionName);

    OpenSSLSignatureContext* signatureCtx =
        (OpenSSLSignatureContext*)((intptr_t)signatureId);
    if (signatureCtx == NULL) {
        logFunctionExit(functionName);
        return;
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE Deleting signature context: %p", signatureCtx);
    }
#endif

    // Free message digest context (also frees pkeyCtx)
    if (signatureCtx->mdCtx != NULL) {
        EVP_MD_CTX_free(signatureCtx->mdCtx);
        signatureCtx->mdCtx = NULL;
        signatureCtx->pkeyCtx = NULL;  // Freed by EVP_MD_CTX_free
    }

    // Free digest algorithm (only if we fetched it)
    if (signatureCtx->md != NULL) {
        EVP_MD_free((EVP_MD*)signatureCtx->md);
        signatureCtx->md = NULL;
    }

    // Free key
    if (signatureCtx->pkey != NULL) {
        EVP_PKEY_free(signatureCtx->pkey);
        signatureCtx->pkey = NULL;
    }

    // Free EdDSA data buffer if allocated
    if (signatureCtx->dataBuffer != NULL) {
        free(signatureCtx->dataBuffer);
        signatureCtx->dataBuffer = NULL;
    }

    // Free structure
    free(signatureCtx);

    logFunctionExit(functionName);
}


