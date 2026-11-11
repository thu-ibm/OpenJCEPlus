/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"

/* CCM constants */
#define MIN_CCM_TAG_SIZE 4
#define MAX_CCM_TAG_SIZE 16
#define MAX_CCM_IV_SIZE  13
#define MIN_CCM_IV_SIZE  7
#define OPENSSL_TAG_MISMATCH_ERROR -6

/*
 * Internal cipher context - opaque handle exchanged as jlong with Java.
 * A handle is single-use and single-threaded: the caller must not use it
 * concurrently and must not call CIPHER_delete more than once.
 * tagLen == 0 means "not initialised / already consumed".
 */
typedef struct {
    EVP_CIPHER_CTX *ctx;         /* OpenSSL cipher context */
    EVP_CIPHER     *cipher;      /* Fetched cipher (EVP_CIPHER_fetch) */
    int             tagLen;      /* Authentication tag length */
    int             updateCount; /* Number of CCM_update calls */
} CipherContext;

/* A pinned Java byte array, remembering whether the JVM handed us a copy. */
typedef struct {
    jbyteArray arr;
    jbyte     *p;
    jboolean   isCopy;
    jsize      len;
} PinnedArray;

/* Pins arr. Returns 1 on success, 0 on failure (exception thrown). */
static int pinArray(JNIEnv *env, PinnedArray *pa, jbyteArray arr, const char *errorMsg)
{
    pa->arr    = arr;
    pa->p      = NULL;
    pa->isCopy = JNI_FALSE;
    pa->len    = 0;

    pa->p = (*env)->GetByteArrayElements(env, arr, &pa->isCopy);
    if (pa->p == NULL) {
        throwOSSLException(env, 0, errorMsg);
        return 0;
    }
    pa->len = (*env)->GetArrayLength(env, arr);
    return 1;
}

/*
 * Releases a pinned array. If the JVM gave us a copy and cleanse is set, the
 * copy is zeroed before being freed (after writing it back when commit is set).
 * Safe to call with an exception pending and with an unpinned array.
 */
static void unpinArray(JNIEnv *env, PinnedArray *pa, int commit, int cleanse)
{
    if (pa->p == NULL) {
        return;
    }
    if (cleanse && pa->isCopy == JNI_TRUE) {
        if (commit) {
            (*env)->ReleaseByteArrayElements(env, pa->arr, pa->p, JNI_COMMIT);
        }
        OPENSSL_cleanse(pa->p, (size_t)pa->len);
        (*env)->ReleaseByteArrayElements(env, pa->arr, pa->p, JNI_ABORT);
    } else {
        (*env)->ReleaseByteArrayElements(env, pa->arr, pa->p, commit ? 0 : JNI_ABORT);
    }
    pa->p = NULL;
}

/* Validates the AAD arguments. Returns 1 if valid, 0 otherwise (exception thrown). */
static int checkAad(JNIEnv *env, jbyteArray aad, jint aadLen, const char *msg)
{
    if (aadLen < 0 || (aad == NULL && aadLen > 0)) {
        throwOSSLException(env, 0, msg);
        return 0;
    }
    if (aadLen > 0) {
        return checkRange(env, aad, 0, aadLen, msg);
    }
    return 1;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1create(
    JNIEnv *env, jclass cls, jlong osslContextId, jstring cipherName)
{
    const char    *cipherNameChars = NULL;
    CipherContext *cipherCtx       = NULL;
    jlong          retCipher       = 0;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherName == NULL) {
        throwOSSLException(env, 0, "CIPHER_create: cipherName is null");
        goto cleanup;
    }

    cipherNameChars = getStringUTFCharsSafe(env, cipherName,
                                            "CIPHER_create: GetStringUTFChars failed");
    if (cipherNameChars == NULL) {
        goto cleanup;
    }

    if (debug) {
        gslogMessage("CIPHER_create: cipher=%s", cipherNameChars);
    }

    cipherCtx = (CipherContext *)mallocSafe(env, sizeof(CipherContext),
                                            "CIPHER_create: malloc CipherContext failed");
    if (cipherCtx == NULL) {
        goto cleanup;
    }

    cipherCtx->cipher      = NULL;
    cipherCtx->ctx         = NULL;
    cipherCtx->tagLen      = 0;
    cipherCtx->updateCount = 0;

    cipherCtx->cipher = EVP_CIPHER_fetch(NULL, cipherNameChars, NULL);
    if (cipherCtx->cipher == NULL) {
        throwOSSLException(env, 0, "CIPHER_create: EVP_CIPHER_fetch failed");
        osslCheckStatus();
        goto cleanup;
    }

    cipherCtx->ctx = EVP_CIPHER_CTX_new();
    if (cipherCtx->ctx == NULL) {
        throwOSSLException(env, 0, "CIPHER_create: EVP_CIPHER_CTX_new failed");
        osslCheckStatus();
        goto cleanup;
    }

    retCipher = (jlong)((intptr_t)cipherCtx);

cleanup:
    releaseStringUTFChars(env, cipherName, cipherNameChars);
    if (retCipher == 0 && cipherCtx != NULL) {
        if (cipherCtx->ctx != NULL) {
            EVP_CIPHER_CTX_free(cipherCtx->ctx);
        }
        if (cipherCtx->cipher != NULL) {
            EVP_CIPHER_free(cipherCtx->cipher);
        }
        free(cipherCtx);
    }
    return retCipher;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1delete(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (cipherCtx == NULL) {
        return;
    }

    if (cipherCtx->ctx != NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
        cipherCtx->ctx = NULL;
    }
    if (cipherCtx->cipher != NULL) {
        EVP_CIPHER_free(cipherCtx->cipher);
        cipherCtx->cipher = NULL;
    }
    free(cipherCtx);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1init(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen)
{
    CipherContext  *cipherCtx   = (CipherContext *)((intptr_t)cipherId);
    EVP_CIPHER_CTX *ctx         = NULL;
    PinnedArray     keyPin      = {0};
    PinnedArray     ivPin       = {0};
    jsize           keyLen      = 0;
    jsize           ivLen       = 0;
    int             expectedKey = 0;
    int             encryptFlag = 0;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOSSLException(env, 0, "CCM_init: invalid cipher context");
        goto cleanup;
    }

    /* Invalidate any previous state; set again only on full success. */
    cipherCtx->tagLen      = 0;
    cipherCtx->updateCount = 0;

    /* Validate tag length (must be in range 4-16 and even) */
    if (tagLen < MIN_CCM_TAG_SIZE || tagLen > MAX_CCM_TAG_SIZE) {
        throwOSSLException(env, 0, "Invalid CCM tag length: must be 4-16 bytes and even");
        goto cleanup;
    }
    if (tagLen % 2 != 0) {
        throwOSSLException(env, 0, "Invalid CCM tag length: must be even");
        goto cleanup;
    }

    if (key == NULL) {
        throwOSSLException(env, 0, "CCM_init: key is null");
        goto cleanup;
    }
    keyLen      = (*env)->GetArrayLength(env, key);
    expectedKey = EVP_CIPHER_get_key_length(cipherCtx->cipher);
    if (expectedKey <= 0 || keyLen != expectedKey) {
        throwOSSLException(env, 0, "Invalid CCM key length for selected cipher");
        goto cleanup;
    }

    if (iv == NULL) {
        throwOSSLException(env, 0, "CCM_init: iv is null");
        goto cleanup;
    }
    ivLen = (*env)->GetArrayLength(env, iv);
    if (ivLen < MIN_CCM_IV_SIZE || ivLen > MAX_CCM_IV_SIZE) {
        throwOSSLException(env, 0, "Invalid CCM IV length: must be 7-13 bytes");
        goto cleanup;
    }

    if (!pinArray(env, &keyPin, key, "CCM_init: GetByteArrayElements key failed")) {
        goto cleanup;
    }
    if (!pinArray(env, &ivPin, iv, "CCM_init: GetByteArrayElements IV failed")) {
        goto cleanup;
    }

    ctx = cipherCtx->ctx;
    encryptFlag = (encrypt != 0) ? 1 : 0;

    /* Reset context to ensure clean state when reinitializing a cached context */
    if (EVP_CIPHER_CTX_reset(ctx) != 1) {
        throwOSSLException(env, 0, "Failed to reset CCM cipher context");
        osslCheckStatus();
        goto cleanup;
    }

    if (EVP_CipherInit_ex(ctx, cipherCtx->cipher, NULL, NULL, NULL, encryptFlag) != 1) {
        throwOSSLException(env, 0, "OpenSSL Failed to initialize CCM cipher");
        osslCheckStatus();
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, (int)ivLen, NULL) != 1) {
        throwOSSLException(env, 0, "OpenSSL Failed to set CCM IV length");
        osslCheckStatus();
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, (int)tagLen, NULL) != 1) {
        throwOSSLException(env, 0, "OpenSSL Failed to set CCM tag length");
        osslCheckStatus();
        goto cleanup;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char *)keyPin.p,
                          (unsigned char *)ivPin.p, encryptFlag) != 1) {
        throwOSSLException(env, 0, "OpenSSL Failed to set CCM key and IV");
        osslCheckStatus();
        goto cleanup;
    }

    cipherCtx->tagLen      = (int)tagLen;
    cipherCtx->updateCount = 0;  /* reset for each new CCM operation */

cleanup:
    /* Key and IV copies made by the JVM are zeroed before being freed. */
    unpinArray(env, &keyPin, 0, 1);
    unpinArray(env, &ivPin, 0, 1);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CCM_update
 * Signature: (JJII[BII[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1update(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen)
{
    CipherContext  *cipherCtx    = (CipherContext *)((intptr_t)cipherId);
    EVP_CIPHER_CTX *ctx          = NULL;
    PinnedArray     inPin        = {0};
    PinnedArray     outPin       = {0};
    PinnedArray     aadPin       = {0};
    unsigned char   emptyIn[1]   = {0};
    unsigned char   emptyOut[1]  = {0};
    const unsigned char *inPtr   = emptyIn;
    unsigned char  *outPtr       = emptyOut;
    int             outLen       = 0;
    int             returnResult = -1;

    (void)cls;
    (void)osslContextId;
    (void)encrypt;

    ERR_clear_error();

    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOSSLException(env, 0, "CCM_update: invalid cipher context");
        goto cleanup;
    }

    if (cipherCtx->tagLen == 0) {
        throwOSSLException(env, 0, "CCM_update: cipher context not initialised");
        goto cleanup;
    }

    /* Validate every argument before touching the OpenSSL context. */
    if (!checkAad(env, aad, aadLen, "CCM_update: invalid AAD range") ||
        !checkRange(env, input, inputOffset, inputLen, "CCM_update: invalid input range") ||
        !checkRange(env, output, outputOffset, inputLen, "CCM_update: output buffer too small")) {
        goto cleanup;
    }

    /* OpenSSL CCM mode only supports a single EVP_CipherUpdate call for data.
     * Reject any attempt to call CCM_update more than once per init. */
    if (cipherCtx->updateCount > 0) {
        throwOSSLException(env, 0,
                           "CCM_update called more than once per operation: "
                           "OpenSSL CCM requires all plaintext in a single update call");
        goto cleanup;
    }
    cipherCtx->updateCount++;

    ctx = cipherCtx->ctx;

    /* Set total plaintext length before AAD/ciphertext */
    outLen = 0;
    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, (int)inputLen) != 1) {
        throwOSSLException(env, 0, "Failed to set CCM plaintext length in update");
        osslCheckStatus();
        goto cleanup;
    }

    /* Process AAD if present */
    if (aadLen > 0) {
        if (!pinArray(env, &aadPin, aad, "CCM_update: GetByteArrayElements AAD failed")) {
            goto cleanup;
        }
        outLen = 0;
        if (EVP_CipherUpdate(ctx, NULL, &outLen, (const unsigned char *)aadPin.p, (int)aadLen) != 1) {
            throwOSSLException(env, 0, "Failed to process AAD");
            osslCheckStatus();
            goto cleanup;
        }
    }

    if (inputLen > 0) {
        if (!pinArray(env, &inPin, input, "CCM_update: GetByteArrayElements input failed") ||
            !pinArray(env, &outPin, output, "CCM_update: GetByteArrayElements output failed")) {
            goto cleanup;
        }
        inPtr  = (const unsigned char *)(inPin.p + inputOffset);
        outPtr = (unsigned char *)(outPin.p + outputOffset);
    }

    outLen = 0;
    if (EVP_CipherUpdate(ctx, outPtr, &outLen, inPtr, (int)inputLen) != 1) {
        throwOSSLException(env, 0, "Failed to update CCM cipher");
        osslCheckStatus();
        goto cleanup;
    }

    returnResult = outLen;

cleanup:
    unpinArray(env, &aadPin, 0, 0);
    unpinArray(env, &inPin, 0, 1);
    unpinArray(env, &outPin, returnResult >= 0, 1);
    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CCM_encryptFinal
 * Signature: (JJ[BII[BII[BIII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1encryptFinal(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen)
{
    CipherContext  *cipherCtx          = (CipherContext *)((intptr_t)cipherId);
    EVP_CIPHER_CTX *ctx                = NULL;
    PinnedArray     inPin              = {0};
    PinnedArray     outPin             = {0};
    PinnedArray     aadPin             = {0};
    unsigned char   emptyBuf[1]        = {0};
    const unsigned char *inPtr         = emptyBuf;
    int             outLen             = 0;
    int             totalOutLen        = 0;
    int             finalLen           = 0;
    int             requiredOutputSize = 0;
    unsigned char   tagBuf[MAX_CCM_TAG_SIZE];
    int             returnResult       = -1;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOSSLException(env, 0, "CCM_encryptFinal: invalid cipher context");
        goto cleanup;
    }

    if (cipherCtx->tagLen == 0) {
        throwOSSLException(env, 0, "CCM_encryptFinal: cipher context not initialised");
        goto cleanup;
    }

    if (tagLen != cipherCtx->tagLen) {
        throwOSSLException(env, 0,
                           "CCM tagLen mismatch: encryptFinal tagLen differs from CCM_init tagLen");
        goto cleanup;
    }

    if (inputLen < 0) {
        throwOSSLException(env, 0, "CCM_encryptFinal: negative input length");
        goto cleanup;
    }
    if ((jlong)inputLen + (jlong)tagLen > (jlong)INT_MAX) {
        throwOSSLException(env, 0, "Output buffer size overflow: inputLen + tagLen exceeds INT_MAX");
        goto cleanup;
    }
    requiredOutputSize = (int)(inputLen + tagLen);

    /* Validate every argument before touching the OpenSSL context. */
    if (!checkRange(env, output, outputOffset, requiredOutputSize,
                    "CCM_encryptFinal: output buffer too small or invalid offset") ||
        !checkRange(env, input, inputOffset, inputLen, "CCM_encryptFinal: invalid input range") ||
        !checkAad(env, aad, aadLen, "CCM_encryptFinal: invalid AAD range")) {
        goto cleanup;
    }

    ctx = cipherCtx->ctx;
    cipherCtx->tagLen = 0;  /* context is consumed by this call; re-init required */

    /* Set total plaintext length */
    outLen = 0;
    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, (int)inputLen) != 1) {
        throwOSSLException(env, 0, "Failed to set CCM plaintext length");
        osslCheckStatus();
        goto cleanup;
    }

    /* Process AAD if present */
    if (aadLen > 0) {
        if (!pinArray(env, &aadPin, aad, "CCM_encryptFinal: GetByteArrayElements AAD failed")) {
            goto cleanup;
        }
        outLen = 0;
        if (EVP_CipherUpdate(ctx, NULL, &outLen, (const unsigned char *)aadPin.p, (int)aadLen) != 1) {
            throwOSSLException(env, 0, "Failed to process AAD");
            osslCheckStatus();
            goto cleanup;
        }
    }

    if (!pinArray(env, &outPin, output, "CCM_encryptFinal: GetByteArrayElements output failed")) {
        goto cleanup;
    }

    if (inputLen > 0) {
        if (!pinArray(env, &inPin, input, "CCM_encryptFinal: GetByteArrayElements input failed")) {
            goto cleanup;
        }
        inPtr = (const unsigned char *)(inPin.p + inputOffset);
    }

    /* A non-NULL input pointer is required for the zero-length case too. */
    outLen = 0;
    if (EVP_CipherUpdate(ctx, (unsigned char *)(outPin.p + outputOffset),
                         &outLen, inPtr, (int)inputLen) != 1) {
        throwOSSLException(env, 0, "Failed to process final input");
        osslCheckStatus();
        goto cleanup;
    }
    totalOutLen += outLen;

    if (inputLen > 0) {
        finalLen = 0;
        if (EVP_CipherFinal_ex(ctx, (unsigned char *)(outPin.p + outputOffset + totalOutLen),
                               &finalLen) != 1) {
            throwOSSLException(env, 0, "Failed to finalize CCM cipher");
            osslCheckStatus();
            goto cleanup;
        }
        totalOutLen += finalLen;
    }

    /* Never write past the space validated above (data + tag). */
    if (totalOutLen < 0 || totalOutLen > inputLen) {
        throwOSSLException(env, 0, "CCM_encryptFinal: unexpected output length");
        goto cleanup;
    }

    /* Get authentication tag and append to output */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, (int)tagLen, tagBuf) != 1) {
        throwOSSLException(env, 0, "Failed to get authentication tag");
        osslCheckStatus();
        goto cleanup;
    }
    memcpy(outPin.p + outputOffset + totalOutLen, tagBuf, (size_t)tagLen);
    totalOutLen += tagLen;

    returnResult = totalOutLen;

cleanup:
    unpinArray(env, &aadPin, 0, 0);
    unpinArray(env, &inPin, 0, 1);   /* plaintext copy */
    unpinArray(env, &outPin, returnResult >= 0, 1);
    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CCM_decryptFinal
 * Signature: (JJ[BII[BII[BIII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1decryptFinal(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen)
{
    CipherContext  *cipherCtx      = (CipherContext *)((intptr_t)cipherId);
    EVP_CIPHER_CTX *ctx            = NULL;
    PinnedArray     inPin          = {0};
    PinnedArray     outPin         = {0};
    PinnedArray     aadPin         = {0};
    unsigned char   emptyBuf[1]    = {0};
    unsigned char   emptyOut[1]    = {0};
    unsigned char  *outPtr         = emptyOut;
    int             actualInputLen = 0;
    int             outLen         = 0;
    int             totalOutLen    = 0;
    int             finalLen       = 0;
    int             returnResult   = -1;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOSSLException(env, 0, "CCM_decryptFinal: invalid cipher context");
        goto cleanup;
    }

    if (cipherCtx->tagLen == 0) {
        throwOSSLException(env, 0, "CCM_decryptFinal: cipher context not initialised");
        goto cleanup;
    }

    if (tagLen != cipherCtx->tagLen) {
        throwOSSLException(env, 0,
                           "CCM tagLen mismatch: decryptFinal tagLen differs from CCM_init tagLen");
        goto cleanup;
    }

    if (inputLen < tagLen) {
        throwOSSLException(env, 0, "Input length less than tag length");
        goto cleanup;
    }
    actualInputLen = inputLen - tagLen;

    /* Validate every argument before touching the OpenSSL context. */
    if (!checkRange(env, output, outputOffset, actualInputLen,
                    "CCM_decryptFinal: output buffer too small or invalid offset") ||
        !checkRange(env, input, inputOffset, inputLen, "CCM_decryptFinal: invalid input range") ||
        !checkAad(env, aad, aadLen, "CCM_decryptFinal: invalid AAD range")) {
        goto cleanup;
    }

    ctx = cipherCtx->ctx;
    cipherCtx->tagLen = 0;  /* context is consumed by this call; re-init required */

    /* Set plaintext length */
    outLen = 0;
    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, actualInputLen) != 1) {
        throwOSSLException(env, 0, "Failed to set CCM plaintext length");
        osslCheckStatus();
        goto cleanup;
    }

    /* Process AAD if present */
    if (aadLen > 0) {
        if (!pinArray(env, &aadPin, aad, "CCM_decryptFinal: GetByteArrayElements AAD failed")) {
            goto cleanup;
        }
        outLen = 0;
        if (EVP_CipherUpdate(ctx, NULL, &outLen, (const unsigned char *)aadPin.p, (int)aadLen) != 1) {
            throwOSSLException(env, 0, "Failed to process AAD");
            osslCheckStatus();
            goto cleanup;
        }
    }

    if (actualInputLen > 0) {
        if (!pinArray(env, &outPin, output, "CCM_decryptFinal: GetByteArrayElements output failed")) {
            goto cleanup;
        }
        outPtr = (unsigned char *)(outPin.p + outputOffset);
    }

    if (!pinArray(env, &inPin, input, "CCM_decryptFinal: GetByteArrayElements input failed")) {
        goto cleanup;
    }

    /* Extract and set tag for verification */
    {
        unsigned char *tag = (unsigned char *)(inPin.p + inputOffset + actualInputLen);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, (int)tagLen, tag) != 1) {
            throwOSSLException(env, 0, "Failed to set authentication tag");
            osslCheckStatus();
            goto cleanup;
        }
    }

    /* A non-NULL input pointer is required for the zero-length case too, otherwise
     * OpenSSL may treat the call as a length/AAD-only call. */
    outLen = 0;
    if (EVP_CipherUpdate(ctx, outPtr, &outLen,
                         (actualInputLen > 0) ? (const unsigned char *)(inPin.p + inputOffset)
                                              : emptyBuf,
                         actualInputLen) != 1) {
        /* The OpenSSL CCM provider verifies the tag in this call and reports a
         * mismatch as PROV_R_CIPHER_OPERATION_FAILED. */
        unsigned long err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PROV &&
            ERR_GET_REASON(err) == PROV_R_CIPHER_OPERATION_FAILED) {
            throwOSSLException(env, 0, "CCM tag verification failed");
            returnResult = OPENSSL_TAG_MISMATCH_ERROR;
        } else {
            throwOSSLException(env, 0, "Failed to process final input");
        }
        osslCheckStatus();
        goto cleanup;
    }
    totalOutLen += outLen;

    finalLen = 0;
    if (EVP_CipherFinal_ex(ctx, outPtr + totalOutLen, &finalLen) != 1) {
        throwOSSLException(env, 0, "Failed to finalize CCM decryption");
        osslCheckStatus();
        goto cleanup;
    }
    totalOutLen += finalLen;

    if (totalOutLen < 0 || totalOutLen > actualInputLen) {
        throwOSSLException(env, 0, "CCM_decryptFinal: unexpected output length");
        returnResult = -1;
        goto cleanup;
    }

    returnResult = totalOutLen;

cleanup:
    /* Do not leave unauthenticated plaintext in a directly pinned output array. */
    if (returnResult < 0 && outPin.p != NULL && outPin.isCopy == JNI_FALSE) {
        OPENSSL_cleanse(outPin.p + outputOffset, (size_t)actualInputLen);
    }
    unpinArray(env, &aadPin, 0, 0);
    unpinArray(env, &inPin, 0, 1);
    unpinArray(env, &outPin, returnResult >= 0, 1);  /* plaintext copy */
    return (jint)returnResult;
}