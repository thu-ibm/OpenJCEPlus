/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLECKey.c
 * @brief EC key generation, import, export and lifecycle via OpenSSL EVP_PKEY.
 *
 * Pattern mirrors OCK/ECKey.c: each key is an EVP_PKEY* stored as a jlong.
 * The Java adapter receives these opaque handles and passes them back for
 * all subsequent operations.
 *
 * Key format conventions (matching OpenSSL / OCK interop):
 *   createPrivateKey  : SEC1 DER ECPrivateKey  (d2i_PrivateKey auto-detects)
 *   createPublicKey   : SubjectPublicKeyInfo DER (d2i_PUBKEY)
 *   getPrivateKeyBytes: SEC1 DER              (i2d_PrivateKey)
 *   getPublicKeyBytes : uncompressed point (04 x y …) extracted via EC_KEY
 *   getParameters     : ECParameters DER (named-curve OID, ASN1 flag = named)
 *
 * OpenSSL 3 deprecates the EC_KEY accessors still used for legacy parameter and
 * raw-point encodings. Migrate those paths to provider-based EVP APIs before
 * OpenSSL 4.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

/* -------------------------------------------------------------------------
 * Curve-size -> OID string table (same NIDs as OCK)
 * -------------------------------------------------------------------------*/
static const char* sizeToOid(int numBits) {
    switch (numBits) {
        case 192: return "1.2.840.10045.3.1.1";   /* P-192 / prime192v1 */
        case 224: return "1.3.132.0.33";            /* P-224 / secp224r1  */
        case 256: return "1.2.840.10045.3.1.7";   /* P-256 / prime256v1 */
        case 384: return "1.3.132.0.34";            /* P-384 / secp384r1  */
        case 521: return "1.3.132.0.35";            /* P-521 / secp521r1  */
        default:  return NULL;
    }
}

/* -------------------------------------------------------------------------
 * Helper: generate an EC key pair given a named-curve NID.
 * Returns EVP_PKEY* on success, NULL on failure (exception already set).
 * -------------------------------------------------------------------------*/
static EVP_PKEY* generateByNid(JNIEnv* env, int nid, const char* functionName) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_CTX_new_id failed");
        logOpenSSLError("EVP_PKEY_CTX_new_id");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_keygen_init failed");
        logOpenSSLError("EVP_PKEY_keygen_init");
        return NULL;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) != 1) {
        EVP_PKEY_CTX_free(pctx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
        logOpenSSLError("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_keygen failed");
        logOpenSSLError("EVP_PKEY_keygen");
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);

    /* Ensure named-curve form is used (OID instead of explicit params) */
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec != NULL) {
        EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
        EC_KEY_free(ec);
    }

    if (debug) {
        gslogMessage("DETAIL_EC generated EVP_PKEY %p nid=%d", pkey, nid);
    }
    return pkey;
}

/* =========================================================================
 * ECKEY_generate(fipsId, numBits) -> jlong (EVP_PKEY*)
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1generate__JI(
    JNIEnv* env, jclass cls, jlong osslContextId, jint numBits)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_generate(size)";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    const char* oidStr = sizeToOid((int)numBits);
    if (oidStr == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "Incorrect key size");
        logFunctionExit(functionName);
        return 0;
    }

    int nid = OBJ_txt2nid(oidStr);
    if (nid == NID_undef) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "OBJ_txt2nid failed for curve OID");
        logOpenSSLError("OBJ_txt2nid");
        logFunctionExit(functionName);
        return 0;
    }

    EVP_PKEY* pkey = generateByNid(env, nid, functionName);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * ECKEY_generate(fipsId, soid) -> jlong (EVP_PKEY*)
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1generate__JLjava_lang_String_2(
    JNIEnv* env, jclass cls, jlong osslContextId, jstring soid)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_generate(soid)";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (soid == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "Curve OID string is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    const char* nativeSoid = getStringUTFCharsSafe(env, soid, functionName,
                                                    "Failed to get curve OID string");
    if (nativeSoid == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    int nid = OBJ_txt2nid(nativeSoid);
    cleanupStringUTFChars(env, soid, nativeSoid);

    if (nid == NID_undef) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "OBJ_txt2nid failed for curve OID string");
        logOpenSSLError("OBJ_txt2nid");
        logFunctionExit(functionName);
        return 0;
    }

    EVP_PKEY* pkey = generateByNid(env, nid, functionName);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * ECKEY_generate(fipsId, paramBytes[]) -> jlong  (from ECParameters DER)
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1generate__J_3B(
    JNIEnv* env, jclass cls, jlong osslContextId, jbyteArray parameterBytes)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_generate(params)";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (parameterBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC parameter bytes are NULL");
        logFunctionExit(functionName);
        return 0;
    }

    jsize paramLen = (*env)->GetArrayLength(env, parameterBytes);
    jbyte* paramData = getByteArrayElementsSafe(env, parameterBytes, functionName,
                                                 "Failed to get EC parameter bytes");
    if (paramData == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    /* Parse ECParameters DER to get the curve NID */
    const unsigned char* p = (const unsigned char*)paramData;
    EC_GROUP* group = d2i_ECPKParameters(NULL, &p, (long)paramLen);
    cleanupByteArray(env, parameterBytes, paramData, JNI_ABORT);

    if (group == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "d2i_ECPKParameters failed");
        logOpenSSLError("d2i_ECPKParameters");
        logFunctionExit(functionName);
        return 0;
    }

    int nid = EC_GROUP_get_curve_name(group);
    EC_GROUP_free(group);

    if (nid == NID_undef) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "Cannot determine curve NID from ECParameters");
        logFunctionExit(functionName);
        return 0;
    }

    EVP_PKEY* pkey = generateByNid(env, nid, functionName);
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * ECKEY_generateParameters(fipsId, numBits) -> byte[]  (ECParameters DER)
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1generateParameters__JI(
    JNIEnv* env, jclass cls, jlong osslContextId, jint numBits)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_generateParameters(size)";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return NULL;
    }

    const char* oidStr = sizeToOid((int)numBits);
    if (oidStr == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "Incorrect key size for generateParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    int nid = OBJ_txt2nid(oidStr);
    if (nid == NID_undef) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "OBJ_txt2nid failed");
        logFunctionExit(functionName);
        return NULL;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC_GROUP_new_by_curve_name failed");
        logOpenSSLError("EC_GROUP_new_by_curve_name");
        logFunctionExit(functionName);
        return NULL;
    }
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    int size = i2d_ECPKParameters(group, NULL);
    if (size <= 0) {
        EC_GROUP_free(group);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_ECPKParameters failed (size)");
        logOpenSSLError("i2d_ECPKParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) {
        EC_GROUP_free(group);
        logFunctionExit(functionName);
        return NULL;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        EC_GROUP_free(group);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    unsigned char* p = (unsigned char*)buf;
    size = i2d_ECPKParameters(group, &p);
    EC_GROUP_free(group);
    (*env)->ReleaseByteArrayElements(env, result, buf, 0);

    if (size <= 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_ECPKParameters failed");
        logOpenSSLError("i2d_ECPKParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * ECKEY_generateParameters(fipsId, soid) -> byte[]
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1generateParameters__JLjava_lang_String_2(
    JNIEnv* env, jclass cls, jlong osslContextId, jstring soid)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_generateParameters(soid)";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return NULL;
    }

    const char* nativeSoid = getStringUTFCharsSafe(env, soid, functionName,
                                                    "Curve OID string is NULL");
    if (nativeSoid == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    int nid = OBJ_txt2nid(nativeSoid);
    cleanupStringUTFChars(env, soid, nativeSoid);

    if (nid == NID_undef) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "OBJ_txt2nid failed for soid");
        logOpenSSLError("OBJ_txt2nid");
        logFunctionExit(functionName);
        return NULL;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC_GROUP_new_by_curve_name failed");
        logOpenSSLError("EC_GROUP_new_by_curve_name");
        logFunctionExit(functionName);
        return NULL;
    }
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    int size = i2d_ECPKParameters(group, NULL);
    if (size <= 0) {
        EC_GROUP_free(group);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_ECPKParameters failed (size)");
        logOpenSSLError("i2d_ECPKParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) {
        EC_GROUP_free(group);
        logFunctionExit(functionName);
        return NULL;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        EC_GROUP_free(group);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    unsigned char* p2 = (unsigned char*)buf;
    size = i2d_ECPKParameters(group, &p2);
    EC_GROUP_free(group);
    (*env)->ReleaseByteArrayElements(env, result, buf, 0);

    if (size <= 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_ECPKParameters failed");
        logOpenSSLError("i2d_ECPKParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * ECKEY_createPrivateKey(fipsId, sec1Bytes[]) -> jlong (EVP_PKEY*)
 * sec1Bytes is SEC1 DER ECPrivateKey — d2i_PrivateKey auto-detects it.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1createPrivateKey(
    JNIEnv* env, jclass cls, jlong osslContextId, jbyteArray privateKeyBytes)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_createPrivateKey";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (privateKeyBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PRIVATE_KEY_FAILED,
                                   "Private key bytes are NULL");
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
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)keyLen);
    cleanupByteArray(env, privateKeyBytes, keyData, JNI_ABORT);

    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PRIVATE_KEY_FAILED,
                                   "d2i_PrivateKey failed for EC private key");
        logOpenSSLError("d2i_PrivateKey(EC)");
        logFunctionExit(functionName);
        return 0;
    }

    /* Ensure named-curve form */
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec != NULL) {
        EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
        EC_KEY_free(ec);
    }

    if (debug) {
        gslogMessage("DETAIL_EC createPrivateKey -> EVP_PKEY %p", pkey);
    }
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * ECKEY_createPublicKey(fipsId, pointBytes[], paramBytes[]) -> jlong
 * pointBytes is raw uncompressed EC point (04 x y).
 * paramBytes is ECParameters DER (named-curve OID).
 * We build SubjectPublicKeyInfo DER and call d2i_PUBKEY.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1createPublicKey(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jbyteArray publicKeyBytes, jbyteArray parameterBytes)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_createPublicKey";
    logFunctionEntry(functionName);

    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, NULL)) {
        logFunctionExit(functionName);
        return 0;
    }

    if (publicKeyBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "Public key bytes are NULL");
        logFunctionExit(functionName);
        return 0;
    }

    jsize pointLen = (*env)->GetArrayLength(env, publicKeyBytes);
    jbyte* pointData = getByteArrayElementsSafe(env, publicKeyBytes, functionName,
                                                 "Failed to get public key bytes");
    if (pointData == NULL) {
        logFunctionExit(functionName);
        return 0;
    }

    jsize paramLen = 0;
    jbyte* paramData = NULL;
    if (parameterBytes != NULL) {
        paramLen = (*env)->GetArrayLength(env, parameterBytes);
        paramData = getByteArrayElementsSafe(env, parameterBytes, functionName,
                                              "Failed to get parameter bytes");
        if (paramData == NULL) {
            cleanupByteArray(env, publicKeyBytes, pointData, JNI_ABORT);
            logFunctionExit(functionName);
            return 0;
        }
    }

    /*
     * Parse ECParameters to get the EC_GROUP, then use that group +
     * the raw point bytes to build an EC_KEY, then wrap in EVP_PKEY.
     */
    EC_GROUP* group = NULL;
    if (paramData != NULL) {
        const unsigned char* pp = (const unsigned char*)paramData;
        group = d2i_ECPKParameters(NULL, &pp, (long)paramLen);
        cleanupByteArray(env, parameterBytes, paramData, JNI_ABORT);
        if (group == NULL) {
            cleanupByteArray(env, publicKeyBytes, pointData, JNI_ABORT);
            setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                       "d2i_ECPKParameters failed");
            logOpenSSLError("d2i_ECPKParameters");
            logFunctionExit(functionName);
            return 0;
        }
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    }

    EC_KEY* ecKey = EC_KEY_new();
    if (ecKey == NULL) {
        if (group) EC_GROUP_free(group);
        cleanupByteArray(env, publicKeyBytes, pointData, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "EC_KEY_new failed");
        logOpenSSLError("EC_KEY_new");
        logFunctionExit(functionName);
        return 0;
    }

    if (group != NULL) {
        EC_KEY_set_group(ecKey, group);
        EC_GROUP_free(group);
        group = NULL;
    }

    EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ecKey));
    if (point == NULL) {
        EC_KEY_free(ecKey);
        cleanupByteArray(env, publicKeyBytes, pointData, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "EC_POINT_new failed");
        logOpenSSLError("EC_POINT_new");
        logFunctionExit(functionName);
        return 0;
    }

    if (EC_POINT_oct2point(EC_KEY_get0_group(ecKey), point,
                            (const unsigned char*)pointData, (size_t)pointLen, NULL) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ecKey);
        cleanupByteArray(env, publicKeyBytes, pointData, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "EC_POINT_oct2point failed");
        logOpenSSLError("EC_POINT_oct2point");
        logFunctionExit(functionName);
        return 0;
    }
    cleanupByteArray(env, publicKeyBytes, pointData, JNI_ABORT);

    if (EC_KEY_set_public_key(ecKey, point) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ecKey);
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "EC_KEY_set_public_key failed");
        logOpenSSLError("EC_KEY_set_public_key");
        logFunctionExit(functionName);
        return 0;
    }
    EC_POINT_free(point);
    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_set1_EC_KEY(pkey, ecKey) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        EC_KEY_free(ecKey);
        setPendingOpenSSLException(env, OPENSSL_EC_CREATE_PUBLIC_KEY_FAILED,
                                   "EVP_PKEY_set1_EC_KEY failed");
        logOpenSSLError("EVP_PKEY_set1_EC_KEY");
        logFunctionExit(functionName);
        return 0;
    }
    EC_KEY_free(ecKey);

    if (debug) {
        gslogMessage("DETAIL_EC createPublicKey -> EVP_PKEY %p", pkey);
    }
    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * ECKEY_getParameters(fipsId, keyId) -> byte[]  (ECParameters / named-curve OID DER)
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1getParameters(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong ecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_getParameters";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)ecKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC key handle is NULL");
        logFunctionExit(functionName);
        return NULL;
    }

    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_get1_EC_KEY failed");
        logOpenSSLError("EVP_PKEY_get1_EC_KEY");
        logFunctionExit(functionName);
        return NULL;
    }

    int size = i2d_ECParameters(ec, NULL);
    if (size <= 0) {
        EC_KEY_free(ec);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_ECParameters failed (size)");
        logOpenSSLError("i2d_ECParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) {
        EC_KEY_free(ec);
        logFunctionExit(functionName);
        return NULL;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        EC_KEY_free(ec);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    unsigned char* p = (unsigned char*)buf;
    size = i2d_ECParameters(ec, &p);
    EC_KEY_free(ec);
    (*env)->ReleaseByteArrayElements(env, result, buf, 0);

    if (size <= 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "i2d_ECParameters failed");
        logOpenSSLError("i2d_ECParameters");
        logFunctionExit(functionName);
        return NULL;
    }

    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * ECKEY_getPrivateKeyBytes(fipsId, keyId) -> byte[]  (SEC1 DER)
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1getPrivateKeyBytes(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong ecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_getPrivateKeyBytes";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)ecKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC key handle is NULL");
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
 * ECKEY_getPublicKeyBytes(fipsId, keyId) -> byte[]  (raw uncompressed point 04 x y)
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1getPublicKeyBytes(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong ecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_getPublicKeyBytes";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)ecKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC key handle is NULL");
        logFunctionExit(functionName);
        return NULL;
    }

    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EVP_PKEY_get1_EC_KEY failed");
        logOpenSSLError("EVP_PKEY_get1_EC_KEY");
        logFunctionExit(functionName);
        return NULL;
    }

    const EC_POINT* pubPoint = EC_KEY_get0_public_key(ec);
    const EC_GROUP* group    = EC_KEY_get0_group(ec);

    /* Measure uncompressed point size */
    size_t ptLen = EC_POINT_point2oct(group, pubPoint,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      NULL, 0, NULL);
    if (ptLen == 0) {
        EC_KEY_free(ec);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC_POINT_point2oct (size) failed");
        logOpenSSLError("EC_POINT_point2oct");
        logFunctionExit(functionName);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)ptLen);
    if (result == NULL) {
        EC_KEY_free(ec);
        logFunctionExit(functionName);
        return NULL;
    }

    jbyte* buf = (*env)->GetByteArrayElements(env, result, NULL);
    if (buf == NULL) {
        EC_KEY_free(ec);
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "GetByteArrayElements failed");
        logFunctionExit(functionName);
        return NULL;
    }

    size_t written = EC_POINT_point2oct(group, pubPoint,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         (unsigned char*)buf, ptLen, NULL);
    EC_KEY_free(ec);
    (*env)->ReleaseByteArrayElements(env, result, buf, 0);

    if (written == 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC_POINT_point2oct failed");
        logOpenSSLError("EC_POINT_point2oct");
        logFunctionExit(functionName);
        return NULL;
    }

    logFunctionExit(functionName);
    return result;
}

/* =========================================================================
 * ECKEY_createPKey(fipsId, ecKeyId) -> jlong
 * In this backend ecKeyId already IS an EVP_PKEY* — bump ref and return same.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1createPKey(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong ecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_createPKey";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)ecKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_EC_GENERATE_FAILED,
                                   "EC key handle is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    /* Increment reference count so the caller can independently free it */
    EVP_PKEY_up_ref(pkey);

    logFunctionExit(functionName);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * ECKEY_delete(fipsId, ecKeyId)
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_ECKEY_1delete(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong ecKeyId)
{
    static const char* functionName = "OpenSSLNativeInterface.ECKEY_delete";
    logFunctionEntry(functionName);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)ecKeyId);
    if (pkey != NULL) {
        if (debug) {
            gslogMessage("DETAIL_EC delete EVP_PKEY %p", pkey);
        }
        EVP_PKEY_free(pkey);
    }

    logFunctionExit(functionName);
}
