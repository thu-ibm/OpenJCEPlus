/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLKeyPairGenerator.c
 * @brief Implementation of key pair generation operations using OpenSSL.
 *
 * This file implements cryptographic key pair generation using OpenSSL's EVP
 * interface. It supports various key generation algorithms including RSA, EC,
 * DSA, EdDSA, and DH.
 *
 * Key features:
 * - Multiple key generation algorithm support via EVP interface
 * - Configurable key sizes and parameters
 * - Support for named curves (EC, EdDSA)
 * - Efficient memory management with proper cleanup
 * - FIPS mode support
 * - Key extraction in standard formats (PKCS#8 for private, X.509 for public)
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
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

/* KeyPairGen context struct and constants (formerly in OpenSSLKeyPairGenerator.h) */
#define KEYPAIR_TYPE_RSA   1
#define KEYPAIR_TYPE_EC    2
#define KEYPAIR_TYPE_DSA   3
#define KEYPAIR_TYPE_EDDSA 4
#define KEYPAIR_TYPE_DH    5

typedef struct {
    EVP_PKEY_CTX* pkeyCtx;
    EVP_PKEY*     pkey;
    int           keyType;
    int           keySize;
    char*         curveName;
    int           fipsMode;
} OpenSSLKeyPairGenContext;

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

//============================================================================
// Helper function to validate key pair generation context
//============================================================================
int validateKeyPairGenContext(JNIEnv* env, jint fipsFlag, jlong keyPairGenId,
                               const char* functionName,
                               OpenSSLKeyPairGenContext** keyPairGenCtx) {
    logFunctionEntry(functionName);

    // Validate FIPS flag
    if (!validateAndGetContext(env, fipsFlag, functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Validate key pair generation context pointer
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)((intptr_t)keyPairGenId);
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_NULL,
                                   "Key pair generation context is NULL");
        if (debug) {
            gslogMessage("DETAIL_KEYPAIRGEN OpenSSL KeyPairGen context is NULL");
        }
        logFunctionExit(functionName);
        return 0;
    }

    // Validate that key was generated
    if (ctx->pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID,
                                   "Key pair generation context is invalid - no key generated");
        if (debug) {
            gslogMessage("DETAIL_KEYPAIRGEN FAILURE: Key pair not generated");
        }
        logFunctionExit(functionName);
        return 0;
    }

    *keyPairGenCtx = ctx;
    return 1;
}

//============================================================================
// Helper function to convert curve name to OpenSSL NID
//============================================================================
int getNIDFromCurveName(const char* curveName) {
    if (curveName == NULL) {
        return 0;
    }

    // Common curve name mappings
    if (strcmp(curveName, "secp256r1") == 0 || strcmp(curveName, "prime256v1") == 0 ||
        strcmp(curveName, "P-256") == 0) {
        return NID_X9_62_prime256v1;
    }
    if (strcmp(curveName, "secp384r1") == 0 || strcmp(curveName, "P-384") == 0) {
        return NID_secp384r1;
    }
    if (strcmp(curveName, "secp521r1") == 0 || strcmp(curveName, "P-521") == 0) {
        return NID_secp521r1;
    }
    if (strcmp(curveName, "secp224r1") == 0 || strcmp(curveName, "P-224") == 0) {
        return NID_secp224r1;
    }

    // Try to get NID by name
    return OBJ_txt2nid(curveName);
}

//============================================================================
// Helper function to convert OpenSSL NID to curve name
//============================================================================
const char* getCurveNameFromNID(int nid) {
    return OBJ_nid2sn(nid);
}

//============================================================================
// KEYPAIRGEN_generateRSA - Generate RSA key pair
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1generateRSA(
    JNIEnv* env, jclass cls, jint fipsFlag, jint keySize, jlong publicExponent) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_generateRSA";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Generating RSA key pair: keySize=%d, publicExponent=%lld",
                     keySize, (long long)publicExponent);
    }

    // Validate key size
    if (keySize < 1024 || keySize > 16384) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID_PARAM,
                                   "Invalid RSA key size (must be 1024-16384 bits)");
        logFunctionExit(functionName);
        return 0;
    }

    // Allocate context structure
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)malloc(sizeof(OpenSSLKeyPairGenContext));
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ALLOC_FAILED,
                                   "Failed to allocate key pair generation context");
        logFunctionExit(functionName);
        return 0;
    }

    memset(ctx, 0, sizeof(OpenSSLKeyPairGenContext));
    ctx->keyType = KEYPAIR_TYPE_RSA;
    ctx->keySize = keySize;
    ctx->fipsMode = fipsFlag;

    // Create key generation context
    ctx->pkeyCtx = EVP_PKEY_CTX_new_from_name(context->libctx, "RSA", NULL);
    if (ctx->pkeyCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create RSA key generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_name");
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx->pkeyCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize RSA key generation");
        logOpenSSLError("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Set RSA key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx->pkeyCtx, keySize) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to set RSA key size");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_keygen_bits");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Set public exponent if specified (default is 65537)
    if (publicExponent > 0) {
        BIGNUM* bn_e = BN_new();
        if (bn_e == NULL || !BN_set_word(bn_e, (unsigned long)publicExponent)) {
            setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                       "Failed to set RSA public exponent");
            logOpenSSLError("BN_set_word");
            if (bn_e) BN_free(bn_e);
            EVP_PKEY_CTX_free(ctx->pkeyCtx);
            free(ctx);
            logFunctionExit(functionName);
            return 0;
        }

        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx->pkeyCtx, bn_e) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                       "Failed to set RSA public exponent");
            logOpenSSLError("EVP_PKEY_CTX_set1_rsa_keygen_pubexp");
            BN_free(bn_e);
            EVP_PKEY_CTX_free(ctx->pkeyCtx);
            free(ctx);
            logFunctionExit(functionName);
            return 0;
        }
        BN_free(bn_e);
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx->pkeyCtx, &ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_GENERATE_FAILED,
                                   "Failed to generate RSA key pair");
        logOpenSSLError("EVP_PKEY_keygen");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN RSA key pair generated successfully: keySize=%d", keySize);
    }

    logFunctionExit(functionName);
    return (jlong)((intptr_t)ctx);
}

//============================================================================
// KEYPAIRGEN_generateEC - Generate EC key pair
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1generateEC(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring curveName) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_generateEC";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Get curve name
    const char* curve = getStringUTFCharsSafe(env, curveName, functionName,
                                              "Curve name is NULL");
    if (curve == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Generating EC key pair: curve=%s", curve);
    }

    // Get curve NID
    int nid = getNIDFromCurveName(curve);
    if (nid == 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID_PARAM,
                                   "Invalid or unsupported curve name");
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Allocate context structure
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)malloc(sizeof(OpenSSLKeyPairGenContext));
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ALLOC_FAILED,
                                   "Failed to allocate key pair generation context");
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    memset(ctx, 0, sizeof(OpenSSLKeyPairGenContext));
    ctx->keyType = KEYPAIR_TYPE_EC;
    ctx->fipsMode = fipsFlag;
    ctx->curveName = strdup(curve);

    // Create key generation context
    ctx->pkeyCtx = EVP_PKEY_CTX_new_from_name(context->libctx, "EC", NULL);
    if (ctx->pkeyCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create EC key generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_name");
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx->pkeyCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize EC key generation");
        logOpenSSLError("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Set the curve
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx->pkeyCtx, nid) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to set EC curve");
        logOpenSSLError("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx->pkeyCtx, &ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_GENERATE_FAILED,
                                   "Failed to generate EC key pair");
        logOpenSSLError("EVP_PKEY_keygen");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN EC key pair generated successfully: curve=%s", curve);
    }

    cleanupStringUTFChars(env, curveName, curve);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)ctx);
}

//============================================================================
// KEYPAIRGEN_generateDSA - Generate DSA key pair
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1generateDSA(
    JNIEnv* env, jclass cls, jint fipsFlag, jint keySize) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_generateDSA";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Generating DSA key pair: keySize=%d", keySize);
    }

    // Validate key size (DSA supports 1024, 2048, 3072)
    if (keySize != 1024 && keySize != 2048 && keySize != 3072) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID_PARAM,
                                   "Invalid DSA key size (must be 1024, 2048, or 3072 bits)");
        logFunctionExit(functionName);
        return 0;
    }

    // Allocate context structure
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)malloc(sizeof(OpenSSLKeyPairGenContext));
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ALLOC_FAILED,
                                   "Failed to allocate key pair generation context");
        logFunctionExit(functionName);
        return 0;
    }

    memset(ctx, 0, sizeof(OpenSSLKeyPairGenContext));
    ctx->keyType = KEYPAIR_TYPE_DSA;
    ctx->keySize = keySize;
    ctx->fipsMode = fipsFlag;

    // Create parameter generation context first
    EVP_PKEY_CTX* paramCtx = EVP_PKEY_CTX_new_from_name(context->libctx, "DSA", NULL);
    if (paramCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create DSA parameter generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_name");
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize parameter generation
    if (EVP_PKEY_paramgen_init(paramCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize DSA parameter generation");
        logOpenSSLError("EVP_PKEY_paramgen_init");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Set DSA key size for parameter generation
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(paramCtx, keySize) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to set DSA parameter size");
        logOpenSSLError("EVP_PKEY_CTX_set_dsa_paramgen_bits");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Generate parameters
    EVP_PKEY* params = NULL;
    if (EVP_PKEY_paramgen(paramCtx, &params) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to generate DSA parameters");
        logOpenSSLError("EVP_PKEY_paramgen");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }
    EVP_PKEY_CTX_free(paramCtx);

    // Create key generation context from parameters
    ctx->pkeyCtx = EVP_PKEY_CTX_new_from_pkey(context->libctx, params, NULL);
    EVP_PKEY_free(params);  // Free parameters, context has a reference
    
    if (ctx->pkeyCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create DSA key generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_pkey");
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx->pkeyCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize DSA key generation");
        logOpenSSLError("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx->pkeyCtx, &ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_GENERATE_FAILED,
                                   "Failed to generate DSA key pair");
        logOpenSSLError("EVP_PKEY_keygen");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN DSA key pair generated successfully: keySize=%d", keySize);
    }

    logFunctionExit(functionName);
    return (jlong)((intptr_t)ctx);
}

//============================================================================
// KEYPAIRGEN_generateEdDSA - Generate EdDSA key pair
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1generateEdDSA(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring curveName) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_generateEdDSA";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    // Get curve name
    const char* curve = getStringUTFCharsSafe(env, curveName, functionName,
                                              "Curve name is NULL");
    if (curve == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Generating EdDSA key pair: curve=%s", curve);
    }

    // Validate curve name (Ed25519 or Ed448)
    if (strcmp(curve, "Ed25519") != 0 && strcmp(curve, "Ed448") != 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID_PARAM,
                                   "Invalid EdDSA curve (must be Ed25519 or Ed448)");
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Allocate context structure
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)malloc(sizeof(OpenSSLKeyPairGenContext));
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ALLOC_FAILED,
                                   "Failed to allocate key pair generation context");
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    memset(ctx, 0, sizeof(OpenSSLKeyPairGenContext));
    ctx->keyType = KEYPAIR_TYPE_EDDSA;
    ctx->fipsMode = fipsFlag;
    ctx->curveName = strdup(curve);

    // Create key generation context
    ctx->pkeyCtx = EVP_PKEY_CTX_new_from_name(context->libctx, curve, NULL);
    if (ctx->pkeyCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create EdDSA key generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_name");
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx->pkeyCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize EdDSA key generation");
        logOpenSSLError("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx->pkeyCtx, &ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_GENERATE_FAILED,
                                   "Failed to generate EdDSA key pair");
        logOpenSSLError("EVP_PKEY_keygen");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx->curveName);
        free(ctx);
        cleanupStringUTFChars(env, curveName, curve);
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN EdDSA key pair generated successfully: curve=%s", curve);
    }

    cleanupStringUTFChars(env, curveName, curve);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)ctx);
}

//============================================================================
// KEYPAIRGEN_generateDH - Generate DH key pair
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1generateDH(
    JNIEnv* env, jclass cls, jint fipsFlag, jint primeSize, jint generator) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_generateDH";
    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, fipsFlag, functionName, &context)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Generating DH key pair: primeSize=%d, generator=%d",
                     primeSize, generator);
    }

    // Validate parameters
    if (primeSize < 1024 || primeSize > 8192) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID_PARAM,
                                   "Invalid DH prime size (must be 1024-8192 bits)");
        logFunctionExit(functionName);
        return 0;
    }

    if (generator != 2 && generator != 5) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID_PARAM,
                                   "Invalid DH generator (must be 2 or 5)");
        logFunctionExit(functionName);
        return 0;
    }

    // Allocate context structure
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)malloc(sizeof(OpenSSLKeyPairGenContext));
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ALLOC_FAILED,
                                   "Failed to allocate key pair generation context");
        logFunctionExit(functionName);
        return 0;
    }

    memset(ctx, 0, sizeof(OpenSSLKeyPairGenContext));
    ctx->keyType = KEYPAIR_TYPE_DH;
    ctx->keySize = primeSize;
    ctx->fipsMode = fipsFlag;

    // Create parameter generation context first
    EVP_PKEY_CTX* paramCtx = EVP_PKEY_CTX_new_from_name(context->libctx, "DH", NULL);
    if (paramCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create DH parameter generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_name");
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize parameter generation
    if (EVP_PKEY_paramgen_init(paramCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize DH parameter generation");
        logOpenSSLError("EVP_PKEY_paramgen_init");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Set DH parameters
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramCtx, primeSize) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to set DH prime size");
        logOpenSSLError("EVP_PKEY_CTX_set_dh_paramgen_prime_len");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_generator(paramCtx, generator) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to set DH generator");
        logOpenSSLError("EVP_PKEY_CTX_set_dh_paramgen_generator");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Generate parameters
    EVP_PKEY* params = NULL;
    if (EVP_PKEY_paramgen(paramCtx, &params) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_PARAM_FAILED,
                                   "Failed to generate DH parameters");
        logOpenSSLError("EVP_PKEY_paramgen");
        EVP_PKEY_CTX_free(paramCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }
    EVP_PKEY_CTX_free(paramCtx);

    // Create key generation context from parameters
    ctx->pkeyCtx = EVP_PKEY_CTX_new_from_pkey(context->libctx, params, NULL);
    EVP_PKEY_free(params);  // Free parameters, context has a reference
    
    if (ctx->pkeyCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_CREATE_FAILED,
                                   "Failed to create DH key generation context");
        logOpenSSLError("EVP_PKEY_CTX_new_from_pkey");
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx->pkeyCtx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INIT_FAILED,
                                   "Failed to initialize DH key generation");
        logOpenSSLError("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx->pkeyCtx, &ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_GENERATE_FAILED,
                                   "Failed to generate DH key pair");
        logOpenSSLError("EVP_PKEY_keygen");
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        free(ctx);
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN DH key pair generated successfully: primeSize=%d", primeSize);
    }

    logFunctionExit(functionName);
    return (jlong)((intptr_t)ctx);
}

//============================================================================
// KEYPAIRGEN_getPrivateKey - Extract private key in PKCS#8 format
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1getPrivateKey(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong keyPairGenId) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_getPrivateKey";
    logFunctionEntry(functionName);

    // Validate context
    OpenSSLKeyPairGenContext* ctx = NULL;
    if (!validateKeyPairGenContext(env, fipsFlag, keyPairGenId, functionName, &ctx)) {
        logFunctionExit(functionName);
        return NULL;
    }

    // Create BIO for encoding
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ENCODE_FAILED,
                                   "Failed to create BIO for private key encoding");
        logOpenSSLError("BIO_new");
        logFunctionExit(functionName);
        return NULL;
    }

    // Encode private key in PKCS#8 format
    if (i2d_PrivateKey_bio(bio, ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ENCODE_FAILED,
                                   "Failed to encode private key");
        logOpenSSLError("i2d_PrivateKey_bio");
        BIO_free(bio);
        logFunctionExit(functionName);
        return NULL;
    }

    // Get encoded data
    BUF_MEM* bufMem;
    BIO_get_mem_ptr(bio, &bufMem);

    // Create Java byte array
    jbyteArray result = (*env)->NewByteArray(env, bufMem->length);
    if (result == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ENCODE_FAILED,
                                   "Failed to allocate byte array for private key");
        BIO_free(bio);
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, bufMem->length, (jbyte*)bufMem->data);
    BIO_free(bio);

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Private key extracted: size=%d bytes", (int)bufMem->length);
    }

    logFunctionExit(functionName);
    return result;
}

//============================================================================
// KEYPAIRGEN_getPublicKey - Extract public key in X.509 format
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1getPublicKey(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong keyPairGenId) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_getPublicKey";
    logFunctionEntry(functionName);

    // Validate context
    OpenSSLKeyPairGenContext* ctx = NULL;
    if (!validateKeyPairGenContext(env, fipsFlag, keyPairGenId, functionName, &ctx)) {
        logFunctionExit(functionName);
        return NULL;
    }

    // Create BIO for encoding
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ENCODE_FAILED,
                                   "Failed to create BIO for public key encoding");
        logOpenSSLError("BIO_new");
        logFunctionExit(functionName);
        return NULL;
    }

    // Encode public key in X.509 SubjectPublicKeyInfo format
    if (i2d_PUBKEY_bio(bio, ctx->pkey) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ENCODE_FAILED,
                                   "Failed to encode public key");
        logOpenSSLError("i2d_PUBKEY_bio");
        BIO_free(bio);
        logFunctionExit(functionName);
        return NULL;
    }

    // Get encoded data
    BUF_MEM* bufMem;
    BIO_get_mem_ptr(bio, &bufMem);

    // Create Java byte array
    jbyteArray result = (*env)->NewByteArray(env, bufMem->length);
    if (result == NULL) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_ENCODE_FAILED,
                                   "Failed to allocate byte array for public key");
        BIO_free(bio);
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, bufMem->length, (jbyte*)bufMem->data);
    BIO_free(bio);

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Public key extracted: size=%d bytes", (int)bufMem->length);
    }

    logFunctionExit(functionName);
    return result;
}

//============================================================================
// KEYPAIRGEN_getKeySize - Get key size in bits
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1getKeySize(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong keyPairGenId) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_getKeySize";
    logFunctionEntry(functionName);

    // Validate context
    OpenSSLKeyPairGenContext* ctx = NULL;
    if (!validateKeyPairGenContext(env, fipsFlag, keyPairGenId, functionName, &ctx)) {
        logFunctionExit(functionName);
        return -1;
    }

    int keySize = EVP_PKEY_get_bits(ctx->pkey);
    if (keySize <= 0) {
        setPendingOpenSSLException(env, OPENSSL_KEYPAIRGEN_INVALID,
                                   "Failed to get key size");
        logOpenSSLError("EVP_PKEY_get_bits");
        logFunctionExit(functionName);
        return -1;
    }

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Key size: %d bits", keySize);
    }

    logFunctionExit(functionName);
    return (jint)keySize;
}

//============================================================================
// KEYPAIRGEN_delete - Delete key pair generation context
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYPAIRGEN_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong keyPairGenId) {
    
    static const char* functionName = "OpenSSLNativeInterface.KEYPAIRGEN_delete";
    logFunctionEntry(functionName);

    // Get context (don't validate fully, just check if non-null)
    OpenSSLKeyPairGenContext* ctx = (OpenSSLKeyPairGenContext*)((intptr_t)keyPairGenId);
    if (ctx == NULL) {
        if (debug) {
            gslogMessage("DETAIL_KEYPAIRGEN Delete called with NULL context");
        }
        logFunctionExit(functionName);
        return;
    }

    // Free OpenSSL structures
    if (ctx->pkey != NULL) {
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = NULL;
    }

    if (ctx->pkeyCtx != NULL) {
        EVP_PKEY_CTX_free(ctx->pkeyCtx);
        ctx->pkeyCtx = NULL;
    }

    if (ctx->curveName != NULL) {
        free(ctx->curveName);
        ctx->curveName = NULL;
    }

    // Free context structure
    free(ctx);

    if (debug) {
        gslogMessage("DETAIL_KEYPAIRGEN Key pair generation context deleted");
    }

    logFunctionExit(functionName);
}


