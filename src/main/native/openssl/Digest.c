/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "OpenSSLContext.h"
#include "OpenSSLHelpers.h"
#include "OpenSSLExceptionCodes.h"

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1create(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring digestAlgo)
{
    EVP_MD     *md              = NULL;
    EVP_MD_CTX *mdCtx           = NULL;
    const char *digestAlgoChars = NULL;
    jlong       digestId        = 0;
    int         rc              = 1;
    OpenSSLContext *context     = NULL;

    if (digestAlgo == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_create: digestAlgo is null");
        return 0;
    }

    if (!validateAndGetContext(env, (jint)(osslContextId - 1),
                               "DIGEST_create", &context)) {
        return 0;
    }

    digestAlgoChars = (*env)->GetStringUTFChars(env, digestAlgo, NULL);
    if (digestAlgoChars == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "DIGEST_create: GetStringUTFChars failed");
        return 0;
    }

    md = EVP_MD_fetch(context->libctx, digestAlgoChars, NULL);
    if (md == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_ALGORITHM_NOT_FOUND,
                                   "DIGEST_create: EVP_MD_fetch failed");
        goto cleanup;
    }

    mdCtx = EVP_MD_CTX_new();
    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_CTX_NEW_FAILED,
                                   "DIGEST_create: EVP_MD_CTX_new failed");
        goto cleanup;
    }

    rc = EVP_DigestInit_ex2(mdCtx, md, NULL);
    if (rc != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_INIT_FAILED,
                                   "DIGEST_create: EVP_DigestInit_ex2 failed");
        goto cleanup;
    }

    digestId = (jlong)(intptr_t)mdCtx;

cleanup:
    /* Always release our fetch reference; mdCtx holds its own ref after init */
    EVP_MD_free(md);
    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);
    if (digestId == 0 && mdCtx != NULL) {
        EVP_MD_CTX_free(mdCtx);
    }
    return digestId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_copy
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1copy(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId)
{
    EVP_MD_CTX *mdCtx     = (EVP_MD_CTX *)(intptr_t)digestId;
    EVP_MD_CTX *mdCtxCopy = NULL;
    jlong       copyId    = 0;

    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_copy: mdCtx is null");
        return 0;
    }

    mdCtxCopy = EVP_MD_CTX_new();
    if (mdCtxCopy == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_CTX_NEW_FAILED,
                                   "DIGEST_copy: EVP_MD_CTX_new failed");
        return 0;
    }

    if (EVP_MD_CTX_copy(mdCtxCopy, mdCtx) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_COPY_FAILED,
                                   "DIGEST_copy: EVP_MD_CTX_copy failed");
        EVP_MD_CTX_free(mdCtxCopy);
        return 0;
    }

    copyId = (jlong)(intptr_t)mdCtxCopy;
    return copyId;
}

//============================================================================
/* Internal helper shared by DIGEST_update and DIGEST_updateFastJNI */
static int digest_update_internal(JNIEnv *env, EVP_MD_CTX *mdCtx,
                                   const unsigned char *data, int dataLen)
{
    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_update: mdCtx is null");
        return 0;
    }
    if (dataLen < 0) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_update: dataLen is negative");
        return 0;
    }
    if (EVP_DigestUpdate(mdCtx, data, (size_t)dataLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_UPDATE_FAILED,
                                   "DIGEST_update: EVP_DigestUpdate failed");
        return 0;
    }
    return 1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_update
 * Signature: (JJ[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1update(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray data, jint offset, jint dataLen)
{
    EVP_MD_CTX    *mdCtx      = (EVP_MD_CTX *)(intptr_t)digestId;
    unsigned char *dataNative = NULL;
    jboolean       isCopy     = 0;
    int            result     = 0;

    if (data == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_update: data array is null");
        return 0;
    }
    if (offset < 0) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_update: offset is negative");
        return 0;
    }

    dataNative = (unsigned char *)(*env)->GetPrimitiveArrayCritical(
        env, data, &isCopy);
    if (dataNative == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "DIGEST_update: GetPrimitiveArrayCritical failed");
        return 0;
    }

    result = digest_update_internal(env, mdCtx, dataNative + offset, dataLen);

    (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
    return (jint)result;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_updateFastJNI
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1updateFastJNI(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jlong dataBuffer, jint dataLen)
{
    EVP_MD_CTX    *mdCtx      = (EVP_MD_CTX *)(intptr_t)digestId;
    unsigned char *dataNative = (unsigned char *)(intptr_t)dataBuffer;

    if (dataNative == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_updateFastJNI: data buffer pointer is null");
        return;
    }
    digest_update_internal(env, mdCtx, dataNative, (int)dataLen);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId)
{
    EVP_MD_CTX    *mdCtx            = (EVP_MD_CTX *)(intptr_t)digestId;
    jbyteArray     digestBytes      = NULL;
    unsigned char *digestBytesNative = NULL;
    unsigned int   digestLen        = 0;
    jbyteArray     result           = NULL;

    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_digest: mdCtx is null");
        return NULL;
    }

    /* Query the output size without finalising */
    digestLen = (unsigned int)EVP_MD_CTX_get_size(mdCtx);
    if (digestLen == 0) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                   "DIGEST_digest: EVP_MD_CTX_get_size returned 0");
        return NULL;
    }

    digestBytes = (*env)->NewByteArray(env, (jsize)digestLen);
    if (digestBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "DIGEST_digest: NewByteArray failed");
        return NULL;
    }

    digestBytesNative = (unsigned char *)(*env)->GetPrimitiveArrayCritical(
        env, digestBytes, NULL);
    if (digestBytesNative == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "DIGEST_digest: GetPrimitiveArrayCritical failed");
        (*env)->DeleteLocalRef(env, digestBytes);
        return NULL;
    }

    if (EVP_DigestFinal_ex(mdCtx, digestBytesNative, &digestLen) != 1) {
        (*env)->ReleasePrimitiveArrayCritical(env, digestBytes,
                                              digestBytesNative, JNI_ABORT);
        (*env)->DeleteLocalRef(env, digestBytes);
        setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                   "DIGEST_digest: EVP_DigestFinal_ex failed");
        return NULL;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, digestBytes,
                                          digestBytesNative, 0);
    result = digestBytes;
    return result;
}

//============================================================================
/* Internal helper for digest-and-reset operations */
static int digest_and_reset_internal(JNIEnv *env, EVP_MD_CTX *mdCtx,
                                      unsigned char *buf, unsigned int len)
{
    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_digest_and_reset: mdCtx is null");
        return 0;
    }
    if (buf == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_digest_and_reset: output buffer is null");
        return 0;
    }

    if (EVP_DigestFinal_ex(mdCtx, buf, &len) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                   "DIGEST_digest_and_reset: EVP_DigestFinal_ex failed");
        return 0;
    }

    /* Reset context for reuse */
    if (EVP_DigestInit_ex2(mdCtx, NULL, NULL) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_INIT_FAILED,
                                   "DIGEST_digest_and_reset: EVP_DigestInit_ex2 (reset) failed");
        return 0;
    }
    return 1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest_and_reset  (long outputBuffer variant)
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest_1and_1reset__JJJI(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jlong outputBuffer, jint length)
{
    EVP_MD_CTX    *mdCtx = (EVP_MD_CTX *)(intptr_t)digestId;
    unsigned char *buf   = (unsigned char *)(intptr_t)outputBuffer;

    digest_and_reset_internal(env, mdCtx, buf, (unsigned int)length);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest_and_reset  (byte[] output variant)
 * Signature: (JJ[B)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest_1and_1reset__JJ_3B(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray output)
{
    EVP_MD_CTX    *mdCtx      = (EVP_MD_CTX *)(intptr_t)digestId;
    unsigned char *buf        = NULL;
    unsigned int   digestLen  = 0;
    int            result     = 0;

    if (output == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_digest_and_reset: output array is null");
        return 0;
    }

    buf = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, output, NULL);
    if (buf == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "DIGEST_digest_and_reset: GetPrimitiveArrayCritical failed");
        return 0;
    }

    result = digest_and_reset_internal(env, mdCtx, buf, digestLen);

    (*env)->ReleasePrimitiveArrayCritical(env, output, buf,
                                          result ? 0 : JNI_ABORT);
    return (jint)result;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_size
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1size(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId)
{
    EVP_MD_CTX *mdCtx     = (EVP_MD_CTX *)(intptr_t)digestId;
    int         digestLen = 0;

    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_size: mdCtx is null");
        return 0;
    }

    digestLen = EVP_MD_CTX_get_size(mdCtx);
    if (digestLen <= 0) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                   "DIGEST_size: EVP_MD_CTX_get_size failed");
        return 0;
    }
    return (jint)digestLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_reset
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1reset(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId)
{
    EVP_MD_CTX *mdCtx = (EVP_MD_CTX *)(intptr_t)digestId;

    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_reset: mdCtx is null");
        return;
    }

    if (EVP_DigestInit_ex2(mdCtx, NULL, NULL) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_INIT_FAILED,
                                   "DIGEST_reset: EVP_DigestInit_ex2 failed");
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1delete(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId)
{
    EVP_MD_CTX *mdCtx = (EVP_MD_CTX *)(intptr_t)digestId;
    if (mdCtx != NULL) {
        EVP_MD_CTX_free(mdCtx);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_PKCS12KeyDeriveHelp
 * Signature: (JJ[BIII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1PKCS12KeyDeriveHelp(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray input, jint offset, jint length, jint iterationCount)
{
    EVP_MD_CTX    *mdCtx      = (EVP_MD_CTX *)(intptr_t)digestId;
    unsigned char *inputNative = NULL;
    int            i;
    int            result     = 0;

    if (input == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "DIGEST_PKCS12KeyDeriveHelp: input is null");
        return 0;
    }
    if (mdCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_NULL,
                                   "DIGEST_PKCS12KeyDeriveHelp: mdCtx is null");
        return 0;
    }

    inputNative = (unsigned char *)(*env)->GetPrimitiveArrayCritical(
        env, input, NULL);
    if (inputNative == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "DIGEST_PKCS12KeyDeriveHelp: GetPrimitiveArrayCritical failed");
        return 0;
    }

    /* First update with the provided input */
    if (EVP_DigestUpdate(mdCtx, inputNative + offset, (size_t)length) != 1) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_DIGEST_UPDATE_FAILED,
                                   "DIGEST_PKCS12KeyDeriveHelp: EVP_DigestUpdate failed");
        return 0;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);

    /* Remaining iterations hash the previous digest output into itself */
    {
        unsigned char  digestBuf[EVP_MAX_MD_SIZE];
        unsigned int   digestLen = 0;

        if (EVP_DigestFinal_ex(mdCtx, digestBuf, &digestLen) != 1) {
            setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                       "DIGEST_PKCS12KeyDeriveHelp: EVP_DigestFinal_ex failed");
            return 0;
        }

        for (i = 1; i < iterationCount; i++) {
            if (EVP_DigestInit_ex2(mdCtx, NULL, NULL) != 1 ||
                EVP_DigestUpdate(mdCtx, digestBuf, digestLen) != 1 ||
                EVP_DigestFinal_ex(mdCtx, digestBuf, &digestLen) != 1) {
                setPendingOpenSSLException(env, OPENSSL_DIGEST_UPDATE_FAILED,
                                           "DIGEST_PKCS12KeyDeriveHelp: iteration failed");
                return 0;
            }
        }

        /* Re-init and load the final digest value back into the context */
        if (EVP_DigestInit_ex2(mdCtx, NULL, NULL) != 1 ||
            EVP_DigestUpdate(mdCtx, digestBuf, digestLen) != 1) {
            setPendingOpenSSLException(env, OPENSSL_DIGEST_UPDATE_FAILED,
                                       "DIGEST_PKCS12KeyDeriveHelp: final reload failed");
            return 0;
        }
    }

    result = (jint)iterationCount;
    return result;
}
