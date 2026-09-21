/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLXECKey.c
 * @brief XEC (X25519, X448) and EdDSA (Ed25519, Ed448) key operations via OpenSSL EVP_PKEY.
 *
 * option ordinals match CurveUtil.CURVE enum:
 *   0=X25519, 1=X448, 2-6=FFDHE*, 7=Ed25519, 8=Ed448
 *
 * Key format conventions:
 *   generate / createPrivateKey : public key raw bytes written to bufferPtr (direct memory)
 *   getPrivateKeyBytes          : SEC1/PKCS8 DER via i2d_PrivateKey
 *   getPublicKeyBytes           : raw public key bytes via EVP_PKEY_get_raw_public_key
 *   createPublicKey             : SubjectPublicKeyInfo DER via d2i_PUBKEY
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/objects.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

/* -------------------------------------------------------------------------
 * Map option ordinal to OpenSSL NID (matches CurveUtil.CURVE ordinals)
 * -------------------------------------------------------------------------*/
static int optionToNID(int option) {
    switch (option) {
        case 0: return NID_X25519;
        case 1: return NID_X448;
        case 7: return NID_ED25519;
        case 8: return NID_ED448;
        default: return NID_undef;
    }
}

/* =========================================================================
 * XECKEY_generate(osslContextId, option, bufferPtr) -> jlong (EVP_PKEY*)
 *
 * Generates XEC/EdDSA key pair.  Raw public key bytes are written to
 * bufferPtr (a FastJNIBuffer direct-memory pointer).
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1generate(
    JNIEnv* env, jclass cls, jlong osslContextId, jint option, jlong bufferPtr)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_generate";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if ((unsigned char*)((intptr_t)bufferPtr) == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XECKEY_generate: bufferPtr is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    int nid = optionToNID((int)option);
    if (nid == NID_undef) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XECKEY_generate: unsupported curve option");
        logFunctionExit(functionName);
        return 0;
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(nid, NULL);
    if (pctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_CTX_new_id failed");
        logOpenSSLError("EVP_PKEY_CTX_new_id");
        logFunctionExit(functionName);
        return 0;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_keygen_init failed");
        logOpenSSLError("EVP_PKEY_keygen_init");
        logFunctionExit(functionName);
        return 0;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_keygen failed");
        logOpenSSLError("EVP_PKEY_keygen");
        logFunctionExit(functionName);
        return 0;
    }
    EVP_PKEY_CTX_free(pctx);

    /* Write raw public key bytes into the FastJNI buffer */
    size_t pubLen = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pubLen) != 1) {
        EVP_PKEY_free(pkey);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_get_raw_public_key (size) failed");
        logOpenSSLError("EVP_PKEY_get_raw_public_key");
        logFunctionExit(functionName);
        return 0;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, (unsigned char*)((intptr_t)bufferPtr), &pubLen) != 1) {
        EVP_PKEY_free(pkey);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_get_raw_public_key failed");
        logOpenSSLError("EVP_PKEY_get_raw_public_key");
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_XEC generated EVP_PKEY %p nid=%d pubLen=%d",
                     pkey, nid, (int)pubLen);
    }
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * XECKEY_createPrivateKey(osslContextId, privateKeyBytes[], bufferPtr) -> jlong
 *
 * Parses private key from DER bytes (d2i_PrivateKey) and writes the
 * corresponding raw public key into bufferPtr.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPrivateKey(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jbyteArray privateKeyBytes, jlong bufferPtr)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_createPrivateKey";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (privateKeyBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PRIVATE_KEY_FAILED,
                                   "XECKEY_createPrivateKey: privateKeyBytes is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    if ((unsigned char*)((intptr_t)bufferPtr) == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PRIVATE_KEY_FAILED,
                                   "XECKEY_createPrivateKey: bufferPtr is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    jsize keyLen = (*env)->GetArrayLength(env, privateKeyBytes);
    jbyte* keyData = getByteArrayElementsSafe(env, privateKeyBytes, functionName,
                                              "Failed to get private key bytes");
    if (keyData == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    const unsigned char* p = (const unsigned char*)keyData;
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_NONE, NULL, &p, (long)keyLen);
    cleanupByteArray(env, privateKeyBytes, keyData, JNI_ABORT);

    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PRIVATE_KEY_FAILED,
                                   "d2i_PrivateKey failed for XEC private key");
        logOpenSSLError("d2i_PrivateKey(XEC)");
        logFunctionExit(functionName);
        return 0;
    }

    /* Write raw public key into the FastJNI buffer */
    size_t pubLen = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pubLen) != 1 ||
        EVP_PKEY_get_raw_public_key(pkey, (unsigned char*)((intptr_t)bufferPtr), &pubLen) != 1) {
        EVP_PKEY_free(pkey);
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PRIVATE_KEY_FAILED,
                                   "EVP_PKEY_get_raw_public_key failed");
        logOpenSSLError("EVP_PKEY_get_raw_public_key");
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_XEC createPrivateKey -> EVP_PKEY %p", pkey);
    }
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * XECKEY_createPublicKey(osslContextId, publicKeyBytes[]) -> jlong
 *
 * publicKeyBytes is SubjectPublicKeyInfo DER — d2i_PUBKEY parses it.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPublicKey(
    JNIEnv* env, jclass cls, jlong osslContextId, jbyteArray publicKeyBytes)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_createPublicKey";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (publicKeyBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "XECKEY_createPublicKey: publicKeyBytes is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    jsize keyLen = (*env)->GetArrayLength(env, publicKeyBytes);
    jbyte* keyData = getByteArrayElementsSafe(env, publicKeyBytes, functionName,
                                              "Failed to get public key bytes");
    if (keyData == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    const unsigned char* p = (const unsigned char*)keyData;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, (long)keyLen);
    cleanupByteArray(env, publicKeyBytes, keyData, JNI_ABORT);

    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "d2i_PUBKEY failed for XEC public key");
        logOpenSSLError("d2i_PUBKEY(XEC)");
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_XEC createPublicKey -> EVP_PKEY %p", pkey);
    }
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * XECKEY_getPrivateKeyBytes(osslContextId, xecKeyId) -> byte[]
 *
 * Returns private key as DER (SEC1/PKCS8) via i2d_PrivateKey.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPrivateKeyBytes(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong xecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_getPrivateKeyBytes";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)xecKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XECKEY_getPrivateKeyBytes: key handle is NULL");
        logFunctionExit(functionName);
        return NULL;
    }

    int size = i2d_PrivateKey(pkey, NULL);
    if (size <= 0) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_PrivateKey failed (size)");
        logOpenSSLError("i2d_PrivateKey");
        logFunctionExit(functionName);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    unsigned char* p = (unsigned char*)buf;
    size = i2d_PrivateKey(pkey, &p);
    (*env)->ReleaseByteArrayElements(env, result, buf, 0);

    if (size <= 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_PrivateKey failed");
        logOpenSSLError("i2d_PrivateKey");
        logFunctionExit(functionName);
        return NULL;
    }

    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * XECKEY_getPublicKeyBytes(osslContextId, xecKeyId) -> byte[]
 *
 * Returns raw public key bytes via EVP_PKEY_get_raw_public_key.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPublicKeyBytes(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong xecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_getPublicKeyBytes";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)xecKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XECKEY_getPublicKeyBytes: key handle is NULL");
        logFunctionExit(functionName);
        return NULL;
    }

    size_t pubLen = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pubLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_get_raw_public_key (size) failed");
        logOpenSSLError("EVP_PKEY_get_raw_public_key");
        logFunctionExit(functionName);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)pubLen);
    if (result == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_PKEY_get_raw_public_key(pkey, (unsigned char*)buf, &pubLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, result, buf, JNI_ABORT);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_get_raw_public_key failed");
        logOpenSSLError("EVP_PKEY_get_raw_public_key");
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, result, buf, 0);
    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * XECKEY_delete(osslContextId, xecKeyId)
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1delete(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong xecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_delete";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)xecKeyId);
    if (pkey != NULL) {
        if (debug) {
            gslogMessage("DETAIL_XEC delete EVP_PKEY %p", pkey);
        }
        EVP_PKEY_free(pkey);
    }
    logFunctionExit(functionName);
}

/* =========================================================================
 * XECKEY_computeECDHSecret(osslContextId, genCtx, pubXecKeyId, privXecKeyId)
 *   -> byte[]  (shared secret)
 *
 * genCtx is unused (kept for API compatibility with OCK variant).
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1computeECDHSecret(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong genCtxUnused, jlong pubXecKeyId, jlong privXecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.XECKEY_computeECDHSecret";
    logFunctionEntry(functionName);

    EVP_PKEY* pubKey  = (EVP_PKEY*)((intptr_t)pubXecKeyId);
    EVP_PKEY* privKey = (EVP_PKEY*)((intptr_t)privXecKeyId);
    EVP_PKEY_CTX* deriveCtx = NULL;
    jbyteArray result = NULL;
    size_t secretLen = 0;
    jbyte* buf = NULL;

    if (pubKey == NULL || privKey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XECKEY_computeECDHSecret: key handle is NULL");
        logFunctionExit(functionName);
        return NULL;
    }

    deriveCtx = EVP_PKEY_CTX_new(privKey, NULL);
    if (deriveCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_CTX_new failed");
        logOpenSSLError("EVP_PKEY_CTX_new");
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_PKEY_derive_init(deriveCtx) != 1) {
        EVP_PKEY_CTX_free(deriveCtx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_derive_init failed");
        logOpenSSLError("EVP_PKEY_derive_init");
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_PKEY_derive_set_peer(deriveCtx, pubKey) != 1) {
        EVP_PKEY_CTX_free(deriveCtx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_derive_set_peer failed");
        logOpenSSLError("EVP_PKEY_derive_set_peer");
        logFunctionExit(functionName);
        return NULL;
    }

    /* Determine secret length */
    if (EVP_PKEY_derive(deriveCtx, NULL, &secretLen) != 1) {
        EVP_PKEY_CTX_free(deriveCtx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_derive (size) failed");
        logOpenSSLError("EVP_PKEY_derive");
        logFunctionExit(functionName);
        return NULL;
    }

    result = (*env)->NewByteArray(env, (jsize)secretLen);
    if (result == NULL) {
        EVP_PKEY_CTX_free(deriveCtx);
        logFunctionExit(functionName);
        return NULL;
    }

    buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        EVP_PKEY_CTX_free(deriveCtx);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_PKEY_derive(deriveCtx, (unsigned char*)buf, &secretLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, result, buf, JNI_ABORT);
        EVP_PKEY_CTX_free(deriveCtx);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_derive failed");
        logOpenSSLError("EVP_PKEY_derive");
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, result, buf, 0);
    EVP_PKEY_CTX_free(deriveCtx);

    if (debug) {
        gslogMessage("DETAIL_XEC computeECDHSecret secretLen=%d", (int)secretLen);
    }
    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * XDHKeyAgreement_init(osslContextId, privId) -> jlong (EVP_PKEY_CTX*)
 *
 * Creates and initializes a key derivation context with the private key.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XDHKeyAgreement_1init(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong privId)
{
    static const char* functionName = "OpenSSLNativeInterface.XDHKeyAgreement_init";
    logFunctionEntry(functionName);

    EVP_PKEY* privKey = (EVP_PKEY*)((intptr_t)privId);
    if (privKey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XDHKeyAgreement_init: private key handle is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    EVP_PKEY_CTX* deriveCtx = EVP_PKEY_CTX_new(privKey, NULL);
    if (deriveCtx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_CTX_new failed");
        logOpenSSLError("EVP_PKEY_CTX_new");
        logFunctionExit(functionName);
        return 0;
    }

    if (EVP_PKEY_derive_init(deriveCtx) != 1) {
        EVP_PKEY_CTX_free(deriveCtx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_derive_init failed");
        logOpenSSLError("EVP_PKEY_derive_init");
        logFunctionExit(functionName);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_XDH init deriveCtx %p", deriveCtx);
    }
    logFunctionExit(functionName);
    return (jlong)((intptr_t)deriveCtx);
}

/* =========================================================================
 * XDHKeyAgreement_setPeer(osslContextId, genCtx, pubId)
 *
 * Sets the peer public key on the derivation context returned by _init.
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XDHKeyAgreement_1setPeer(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong genCtx, jlong pubId)
{
    static const char* functionName = "OpenSSLNativeInterface.XDHKeyAgreement_setPeer";
    logFunctionEntry(functionName);

    EVP_PKEY_CTX* deriveCtx = (EVP_PKEY_CTX*)((intptr_t)genCtx);
    EVP_PKEY*     pubKey    = (EVP_PKEY*)((intptr_t)pubId);

    if (deriveCtx == NULL || pubKey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "XDHKeyAgreement_setPeer: NULL handle");
        logFunctionExit(functionName);
        return;
    }

    if (EVP_PKEY_derive_set_peer(deriveCtx, pubKey) != 1) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_derive_set_peer failed");
        logOpenSSLError("EVP_PKEY_derive_set_peer");
    }

    logFunctionExit(functionName);
}
