/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLRSAPSS.c
 * @brief RSA-PSS streaming signature operations via OpenSSL EVP interface.
 *
 * Mirrors the OCK RsaPss.c API contract so that the existing Java provider
 * layer (SignatureRSAPSS.java) can drive it without modification.
 *
 * Context lifecycle:
 *   RSAPSS_createContext  - allocate OpenSSLRSAPSSContext, store digest names
 *   RSAPSS_signInit       - bind a private key, initialise EVP_DigestSignInit
 *   RSAPSS_verifyInit     - bind a public  key, initialise EVP_DigestVerifyInit
 *   RSAPSS_digestUpdate   - feed data via EVP_DigestSignUpdate / VerifyUpdate
 *   RSAPSS_getSigLen      - return EVP_PKEY_get_size of the bound key
 *   RSAPSS_signFinal      - EVP_DigestSignFinal into caller-supplied buffer
 *   RSAPSS_verifyFinal    - EVP_DigestVerifyFinal
 *   RSAPSS_reset          - reinitialise the context for reuse
 *   RSAPSS_releaseContext - free all resources
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

/* Operation mode flags */
#define RSAPSS_MODE_UNSET  0
#define RSAPSS_MODE_SIGN   1
#define RSAPSS_MODE_VERIFY 2

/**
 * Internal context structure for RSA-PSS streaming operations.
 */
typedef struct {
    EVP_MD_CTX*   mdCtx;       /* Streaming digest / signature context   */
    EVP_PKEY*     pkey;        /* Bound key (not owned; caller manages)   */
    EVP_PKEY_CTX* pkeyCtx;    /* PSS parameter context (owned by mdCtx)  */
    const EVP_MD* md;          /* Message digest (owned)                  */
    const EVP_MD* mgf1Md;      /* MGF1 digest   (owned)                  */
    int           mode;        /* SIGN or VERIFY                          */
    int           saltlen;     /* PSS salt length (stored for reset)      */
    int           sigLen;      /* Max signature bytes from EVP_PKEY_get_size */
    char          digestName[64];   /* Digest algorithm name for reset    */
    char          mgf1Name[64];     /* MGF1 digest name for reset         */
} OpenSSLRSAPSSContext;

/* =========================================================================
 * Helper: initialise (or re-initialise) the EVP_MD_CTX for sign or verify.
 * Sets PSS padding, salt length, and MGF1 digest on the EVP_PKEY_CTX.
 * Returns 1 on success, 0 on failure (exception already pending).
 * =========================================================================*/
static int rsapss_init_impl(JNIEnv* env, OpenSSLRSAPSSContext* ctx,
                             EVP_PKEY* pkey, int mode, int saltlen,
                             const char* fn)
{
    /* Reset any previous state */
    EVP_MD_CTX_reset(ctx->mdCtx);
    ctx->pkeyCtx = NULL;

    /* Initialise sign or verify */
    int rc;
    if (mode == RSAPSS_MODE_SIGN) {
        rc = EVP_DigestSignInit(ctx->mdCtx, &ctx->pkeyCtx,
                                ctx->md, NULL, pkey);
    } else {
        rc = EVP_DigestVerifyInit(ctx->mdCtx, &ctx->pkeyCtx,
                                  ctx->md, NULL, pkey);
    }
    if (rc != 1) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INIT_FAILED,
                                   "EVP_DigestSignInit/VerifyInit failed for RSA-PSS");
        logOpenSSLError(mode == RSAPSS_MODE_SIGN ?
                       "EVP_DigestSignInit" : "EVP_DigestVerifyInit");
        return 0;
    }

    /* Set PSS padding */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx->pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                   "Failed to set RSA_PKCS1_PSS_PADDING");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_padding");
        return 0;
    }

    /* Set salt length */
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx->pkeyCtx, saltlen) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                   "Failed to set PSS salt length");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        return 0;
    }

    /* Set MGF1 digest */
    if (ctx->mgf1Md != NULL) {
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx->pkeyCtx, ctx->mgf1Md) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_SIGNATURE_PSS_PARAM_FAILED,
                                       "Failed to set MGF1 digest");
            logOpenSSLError("EVP_PKEY_CTX_set_rsa_mgf1_md");
            return 0;
        }
    }

    ctx->mode    = mode;
    ctx->pkey    = pkey;
    ctx->saltlen = saltlen;
    return 1;
}

/* =========================================================================
 * RSAPSS_createContext
 * Allocates the context, fetches the two digests, creates EVP_MD_CTX.
 * Returns context handle or 0 on failure.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1createContext(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jstring digestAlgo, jstring mgf1SpecAlgo)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_createContext";
    logFunctionEntry(fn);

    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), fn, &context)) {
        logFunctionExit(fn);
        return 0L;
    }

    const char* digestName =
        getStringUTFCharsSafe(env, digestAlgo, fn, "digestAlgo is NULL");
    if (digestName == NULL) { logFunctionExit(fn); return 0L; }

    const char* mgf1Name =
        getStringUTFCharsSafe(env, mgf1SpecAlgo, fn, "mgf1SpecAlgo is NULL");
    if (mgf1Name == NULL) {
        cleanupStringUTFChars(env, digestAlgo, digestName);
        logFunctionExit(fn);
        return 0L;
    }

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        cleanupStringUTFChars(env, digestAlgo, digestName);
        cleanupStringUTFChars(env, mgf1SpecAlgo, mgf1Name);
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "calloc failed for OpenSSLRSAPSSContext");
        logFunctionExit(fn);
        return 0L;
    }

    /* Stash names for reset */
    strncpy(ctx->digestName, digestName, sizeof(ctx->digestName) - 1);
    strncpy(ctx->mgf1Name,   mgf1Name,   sizeof(ctx->mgf1Name)   - 1);

    /* Fetch message digest */
    ctx->md = fetchDigestSafe(env, context, digestName, fn,
                              OPENSSL_SIGNATURE_ALGORITHM_NOT_FOUND,
                              "Failed to fetch PSS digest algorithm");
    if (ctx->md == NULL) {
        free(ctx);
        cleanupStringUTFChars(env, digestAlgo, digestName);
        cleanupStringUTFChars(env, mgf1SpecAlgo, mgf1Name);
        logFunctionExit(fn);
        return 0L;
    }

    /* Fetch MGF1 digest */
    ctx->mgf1Md = fetchDigestSafe(env, context, mgf1Name, fn,
                                  OPENSSL_SIGNATURE_ALGORITHM_NOT_FOUND,
                                  "Failed to fetch PSS MGF1 digest algorithm");
    if (ctx->mgf1Md == NULL) {
        EVP_MD_free((EVP_MD*)ctx->md);
        free(ctx);
        cleanupStringUTFChars(env, digestAlgo, digestName);
        cleanupStringUTFChars(env, mgf1SpecAlgo, mgf1Name);
        logFunctionExit(fn);
        return 0L;
    }

    /* Create EVP_MD_CTX */
    ctx->mdCtx = createMDCtxSafe(env, fn,
                                 OPENSSL_SIGNATURE_CTX_NEW_FAILED,
                                 "Failed to create EVP_MD_CTX for RSA-PSS");
    if (ctx->mdCtx == NULL) {
        EVP_MD_free((EVP_MD*)ctx->mgf1Md);
        EVP_MD_free((EVP_MD*)ctx->md);
        free(ctx);
        cleanupStringUTFChars(env, digestAlgo, digestName);
        cleanupStringUTFChars(env, mgf1SpecAlgo, mgf1Name);
        logFunctionExit(fn);
        return 0L;
    }

    cleanupStringUTFChars(env, digestAlgo, digestName);
    cleanupStringUTFChars(env, mgf1SpecAlgo, mgf1Name);
    logFunctionExit(fn);
    return (jlong)((intptr_t)ctx);
}

/* =========================================================================
 * RSAPSS_releaseContext - free all resources
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1releaseContext(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaPssId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_releaseContext";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    if (ctx == NULL) { logFunctionExit(fn); return; }

    if (ctx->mdCtx   != NULL) { EVP_MD_CTX_free(ctx->mdCtx);      ctx->mdCtx   = NULL; }
    if (ctx->md      != NULL) { EVP_MD_free((EVP_MD*)ctx->md);     ctx->md      = NULL; }
    if (ctx->mgf1Md  != NULL) { EVP_MD_free((EVP_MD*)ctx->mgf1Md); ctx->mgf1Md  = NULL; }
    /* pkey is not owned here — caller owns the key handle */
    free(ctx);
    logFunctionExit(fn);
}

/* =========================================================================
 * RSAPSS_signInit - bind private key and initialise for signing
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1signInit(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong rsaPssId, jlong pkeyId, jint saltlen, jboolean convert)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_signInit";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    EVP_PKEY* pkey            = (EVP_PKEY*)((intptr_t)pkeyId);
    if (ctx == NULL || pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "NULL argument to RSAPSS_signInit");
        logFunctionExit(fn);
        return -1;
    }

    if (!rsapss_init_impl(env, ctx, pkey, RSAPSS_MODE_SIGN, (int)saltlen, fn)) {
        logFunctionExit(fn);
        return -1;
    }

    ctx->sigLen = EVP_PKEY_get_size(pkey);
    logFunctionExit(fn);
    return 0;
}

/* =========================================================================
 * RSAPSS_verifyInit - bind public key and initialise for verification
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1verifyInit(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong rsaPssId, jlong pkeyId, jint saltlen)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_verifyInit";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    EVP_PKEY* pkey            = (EVP_PKEY*)((intptr_t)pkeyId);
    if (ctx == NULL || pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "NULL argument to RSAPSS_verifyInit");
        logFunctionExit(fn);
        return -1;
    }

    if (!rsapss_init_impl(env, ctx, pkey, RSAPSS_MODE_VERIFY, (int)saltlen, fn)) {
        logFunctionExit(fn);
        return -1;
    }

    ctx->sigLen = EVP_PKEY_get_size(pkey);
    logFunctionExit(fn);
    return 0;
}

/* =========================================================================
 * RSAPSS_digestUpdate - feed data into the streaming context
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1digestUpdate(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong rsaPssId, jbyteArray data, jint offset, jint dataLen)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_digestUpdate";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    if (ctx == NULL || ctx->mdCtx == NULL || data == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "NULL argument to RSAPSS_digestUpdate");
        logFunctionExit(fn);
        return;
    }

    if (dataLen == 0) { logFunctionExit(fn); return; }

    jbyte* dataNat = getByteArrayElementsSafe(env, data, fn, "Failed to get data bytes");
    if (dataNat == NULL) { logFunctionExit(fn); return; }

    int rc;
    if (ctx->mode == RSAPSS_MODE_SIGN) {
        rc = EVP_DigestSignUpdate(ctx->mdCtx,
                                  (unsigned char*)dataNat + offset,
                                  (size_t)dataLen);
    } else {
        rc = EVP_DigestVerifyUpdate(ctx->mdCtx,
                                    (unsigned char*)dataNat + offset,
                                    (size_t)dataLen);
    }

    cleanupByteArray(env, data, dataNat, JNI_ABORT);

    if (rc != 1) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_UPDATE_FAILED,
                                   "EVP_DigestSign/VerifyUpdate failed for RSA-PSS");
        logOpenSSLError(ctx->mode == RSAPSS_MODE_SIGN ?
                       "EVP_DigestSignUpdate" : "EVP_DigestVerifyUpdate");
    }
    logFunctionExit(fn);
}

/* =========================================================================
 * RSAPSS_getSigLen - return the maximum RSA signature size in bytes
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1getSigLen(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaPssId)
{
    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    if (ctx == NULL) return -1;
    return (jint)ctx->sigLen;
}

/* =========================================================================
 * RSAPSS_signFinal - finalise and write signature into caller's buffer
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1signFinal(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong rsaPssId, jbyteArray signature, jint length)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_signFinal";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    if (ctx == NULL || ctx->mdCtx == NULL || signature == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "NULL argument to RSAPSS_signFinal");
        logFunctionExit(fn);
        return;
    }

    unsigned char* sigBuf = (unsigned char*)malloc((size_t)length);
    if (sigBuf == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "malloc failed in RSAPSS_signFinal");
        logFunctionExit(fn);
        return;
    }

    size_t sigLen = (size_t)length;
    int rc = EVP_DigestSignFinal(ctx->mdCtx, sigBuf, &sigLen);
    if (rc != 1) {
        free(sigBuf);
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_SIGN_FAILED,
                                   "EVP_DigestSignFinal failed for RSA-PSS");
        logOpenSSLError("EVP_DigestSignFinal");
        logFunctionExit(fn);
        return;
    }

    (*env)->SetByteArrayRegion(env, signature, 0, (jsize)sigLen, (jbyte*)sigBuf);
    free(sigBuf);
    logFunctionExit(fn);
}

/* =========================================================================
 * RSAPSS_verifyFinal - finalise and verify signature
 * =========================================================================*/
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1verifyFinal(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong rsaPssId, jbyteArray sigBytes, jint length)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_verifyFinal";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    if (ctx == NULL || ctx->mdCtx == NULL || sigBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_INVALID,
                                   "NULL argument to RSAPSS_verifyFinal");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    jbyte* sigNat = getByteArrayElementsSafe(env, sigBytes, fn, "Failed to get sigBytes");
    if (sigNat == NULL) { logFunctionExit(fn); return JNI_FALSE; }

    int rc = EVP_DigestVerifyFinal(ctx->mdCtx,
                                   (unsigned char*)sigNat, (size_t)length);
    cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);

    if (rc == 1) {
        logFunctionExit(fn);
        return JNI_TRUE;
    }
    if (rc != 0) {
        /* rc < 0 or any unexpected value: a genuine error */
        setPendingOpenSSLException(env, OPENSSL_SIGNATURE_VERIFY_FAILED,
                                   "EVP_DigestVerifyFinal failed for RSA-PSS");
        logOpenSSLError("EVP_DigestVerifyFinal");
    }
    /* rc == 0 means signature invalid — not an exception, just false */
    logFunctionExit(fn);
    return JNI_FALSE;
}

/* =========================================================================
 * RSAPSS_reset - reinitialise context for reuse with the same key
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAPSS_1reset(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaPssId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAPSS_reset";
    logFunctionEntry(fn);

    OpenSSLRSAPSSContext* ctx = (OpenSSLRSAPSSContext*)((intptr_t)rsaPssId);
    if (ctx == NULL || ctx->pkey == NULL) {
        /* Nothing to reset, or no key bound yet */
        logFunctionExit(fn);
        return;
    }

    rsapss_init_impl(env, ctx, ctx->pkey, ctx->mode, ctx->saltlen, fn);
    logFunctionExit(fn);
}
