/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHelpers.c
 * @brief Implementation of common helper functions for OpenSSL JNI operations.
 *
 * This file implements utility functions that are used across all OpenSSL
 * native code to provide consistent error handling, parameter validation,
 * resource management, and JNI operations.
 *
 * The helpers are organized into functional groups:
 * - Logging: Debug logging with function entry/exit tracking
 * - Context validation: FIPS mode and context management
 * - String handling: Safe UTF-8 string conversion and cleanup
 * - Byte array handling: Safe JNI array access and cleanup
 * - Validation: Parameter range and bounds checking
 * - OpenSSL objects: Safe fetching and creation of EVP objects
 * - Memory: Safe allocation with error handling
 * - AAD processing: Common authenticated encryption data handling
 */

#include "OpenSSLHelpers.h"
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

//============================================================================
// Logging Helpers
//============================================================================

void logFunctionEntry(const char* functionName) {
    if (debug) {
        gslogFunctionEntry(functionName);
    }
}

void logFunctionExit(const char* functionName) {
    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
// Context Validation
//============================================================================

int validateAndGetContext(JNIEnv* env, jint fipsFlag,
                          const char* functionName,
                          OpenSSLContext** outContext) {
    int isFIPS = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);
    
    if (context == NULL) {
        return 0;
    }
    
    if (outContext != NULL) {
        *outContext = context;
    }
    
    return 1;
}

//============================================================================
// String Helpers
//============================================================================

const char* getStringUTFCharsSafe(JNIEnv* env, jstring javaString,
                                  const char* functionName,
                                  const char* errorMsg) {
    if (javaString == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    
    const char* str = (*env)->GetStringUTFChars(env, javaString, NULL);
    if (str == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get UTF string");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    
    return str;
}

void cleanupStringUTFChars(JNIEnv* env, jstring javaString, const char* str) {
    if (str != NULL && javaString != NULL) {
        (*env)->ReleaseStringUTFChars(env, javaString, str);
    }
}

//============================================================================
// Byte Array Helpers
//============================================================================

jbyte* getByteArrayElementsSafe(JNIEnv* env, jbyteArray array,
                                const char* functionName,
                                const char* errorMsg) {
    if (array == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    
    jbyte* bytes = (*env)->GetByteArrayElements(env, array, NULL);
    if (bytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                            "Failed to get byte array elements");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    
    return bytes;
}

void cleanupByteArray(JNIEnv* env, jbyteArray array,
                      jbyte* bytes, jint mode) {
    if (bytes != NULL && array != NULL) {
        (*env)->ReleaseByteArrayElements(env, array, bytes, mode);
    }
}

void cleanupByteArrays(JNIEnv* env,
                       jbyteArray keyArray, jbyte* keyBytes,
                       jbyteArray ivArray, jbyte* ivBytes) {
    if (keyBytes != NULL && keyArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, keyArray, keyBytes, JNI_ABORT);
    }
    if (ivBytes != NULL && ivArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, ivArray, ivBytes, JNI_ABORT);
    }
}

void cleanupIOArrays(JNIEnv* env,
                     jbyteArray inputArray, jbyte* inputBytes,
                     jbyteArray outputArray, jbyte* outputBytes,
                     jboolean commitOutput) {
    if (inputBytes != NULL && inputArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArray, inputBytes, JNI_ABORT);
    }
    if (outputBytes != NULL && outputArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, outputArray, outputBytes,
                                         commitOutput ? 0 : JNI_ABORT);
    }
}

//============================================================================
// Validation Helper Functions
//============================================================================

int validateIntRange(JNIEnv* env, jint value, jint min, jint max,
                     const char* functionName, const char* errorMsg) {
    if (value < min || value > max) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

int validateArrayLength(JNIEnv* env, jbyteArray array, jint min, jint max,
                        const char* functionName, const char* errorMsg) {
    jsize length = (*env)->GetArrayLength(env, array);
    if (length < min || length > max) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

int validateOutputBuffer(JNIEnv* env, jbyteArray output, jint outputOffset,
                         jint requiredSize, const char* functionName,
                         const char* errorMsg) {
    if (outputOffset < 0) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    
    jsize outputLength = (*env)->GetArrayLength(env, output);
    if (outputOffset + requiredSize > outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

int validateOffsetAndLength(JNIEnv* env, jint arrayLength,
                            jint offset, jint length,
                            const char* functionName,
                            const char* errorMsg) {
    if (offset < 0 || length < 0 || offset > arrayLength - length) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

//============================================================================
// OpenSSL Object Fetch Helpers
//============================================================================

const EVP_MD* fetchDigestSafe(JNIEnv* env, OpenSSLContext* context,
                               const char* algoName, const char* functionName,
                               int errorCode, const char* errorMsg) {
    const EVP_MD* md = EVP_MD_fetch(context->libctx, algoName, NULL);
    if (md == NULL) {
        throwOpenSSLException(env, errorCode, errorMsg);
        logOpenSSLError("EVP_MD_fetch");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    return md;
}

EVP_KDF* fetchKDFSafe(JNIEnv* env, OpenSSLContext* context,
                      const char* kdfName, const char* functionName,
                      int errorCode, const char* errorMsg) {
    if (debug) {
        gslogMessage("DETAIL fetchKDFSafe: kdfName=%s, context=%p, libctx=%p",
                    kdfName, context, context ? context->libctx : NULL);
    }
    
    EVP_KDF* kdf = EVP_KDF_fetch(context->libctx, kdfName, NULL);
    
    if (debug) {
        gslogMessage("DETAIL fetchKDFSafe: EVP_KDF_fetch returned %p", kdf);
    }
    
    if (kdf == NULL) {
        throwOpenSSLException(env, errorCode, errorMsg);
        logOpenSSLError("EVP_KDF_fetch");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    return kdf;
}

EVP_CIPHER_CTX* createCipherCtxSafe(JNIEnv* env, const char* functionName,
                                    int errorCode, const char* errorMsg) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        throwOpenSSLException(env, errorCode, errorMsg);
        logOpenSSLError("EVP_CIPHER_CTX_new");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    return ctx;
}

HMAC_CTX* createHMACCtxSafe(JNIEnv* env, const char* functionName,
                            int errorCode, const char* errorMsg) {
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        throwOpenSSLException(env, errorCode, errorMsg);
        logOpenSSLError("HMAC_CTX_new");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    return ctx;
}

EVP_MD_CTX* createMDCtxSafe(JNIEnv* env, const char* functionName,
                            int errorCode, const char* errorMsg) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        throwOpenSSLException(env, errorCode, errorMsg);
        logOpenSSLError("EVP_MD_CTX_new");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    return ctx;
}

//============================================================================
// Memory Helpers
//============================================================================

void* mallocSafe(JNIEnv* env, size_t size, const char* errorMsg) {
    void* ptr = malloc(size);
    if (ptr == NULL) {
        throwOpenSSLException(env, OPENSSL_ALLOCATION_FAILED, errorMsg);
        return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}

jbyteArray newByteArraySafe(JNIEnv* env, jsize length, const char* errorMsg) {
    jbyteArray array = (*env)->NewByteArray(env, length);
    if (array == NULL) {
        throwOpenSSLException(env, OPENSSL_ALLOCATION_FAILED, errorMsg);
        return NULL;
    }
    return array;
}

//============================================================================
// AAD Processing Helper (for GCM/CCM)
//============================================================================

int processAAD(JNIEnv* env, EVP_CIPHER_CTX* ctx,
               const unsigned char* aad, int aadLen,
               const char* functionName) {
    if (aad == NULL || aadLen <= 0) {
        return 1;
    }
    
    int outLen = 0;
    int result = EVP_CipherUpdate(ctx, NULL, &outLen, aad, aadLen);
    
    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                            "Failed to process AAD");
        logOpenSSLError("EVP_CipherUpdate(AAD)");
        logFunctionExit(functionName);
        return 0;
    }
    
#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER AAD processed: %d bytes", aadLen);
    }
#endif
    
    return 1;
}


