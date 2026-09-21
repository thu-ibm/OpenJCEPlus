/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLDSAKey.c
 * @brief DSA key generation, import/export, parameter handling,
 *        and sign/verify operations via OpenSSL's low-level DSA API.
 *
 * All key handles are DSA* values stored as jlong; EVP_PKEY* handles are
 * used only where the Java layer explicitly requests one (DSAKEY_createPKey).
 *
 * Key format conventions:
 *   generate (bits)        : DSA* containing both public and private key material
 *   generate (params)      : DSA* built from caller-supplied DER parameters
 *   generateParameters     : DER-encoded DSAparams returned as byte[]
 *   createPrivateKey       : DSA* from OpenSSL DSAPrivateKey DER (d2i_DSAPrivateKey)
 *   createPublicKey        : DSA* from OpenSSL DSAPublicKey DER  (d2i_DSAPublicKey)
 *   getPrivateKeyBytes     : OpenSSL DSAPrivateKey DER (i2d_DSAPrivateKey)
 *   getPublicKeyBytes      : OpenSSL DSAPublicKey DER  (i2d_DSAPublicKey)
 *   getParameters          : DER-encoded DSAparams  (i2d_DSAparams)
 *   createPKey             : EVP_PKEY* wrapping a DSA* (EVP_PKEY_set1_DSA — adds refcount)
 *
 * Error handling:
 *   DSA_ERROR is an alias for OPENSSL_RSA_FAILED (0x00000038). No dedicated
 *   DSA error codes exist in OpenSSLExceptionCodes.h; this alias will be
 *   replaced once DSA-specific codes are added.
 *
 * Deprecation note:
 *   The low-level DSA_*, d2i_DSA*, and i2d_DSA* functions used here are
 *   deprecated in OpenSSL 3 and will be removed in OpenSSL 4. All key
 *   generation, encoding, and raw-digest signing should be migrated to the
 *   EVP_PKEY API before that transition.
 *
 * Sign/verify behaviour:
 *   - DSAKEY_signData / DSAKEY_verifyData: sign/verify a pre-computed digest
 *     passed as raw bytes from the Java layer (NONEwithDSA path).  NID_undef
 *     is passed to DSA_sign/DSA_verify so no additional DigestInfo wrapping
 *     is applied.
 *   - DSAKEY_signDigestCtx / DSAKEY_verifyDigestCtx: finalise a live
 *     EVP_MD_CTX, then call DSA_sign/DSA_verify.  The NID is obtained from
 *     the context (SHA*withDSA path).
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLHelpers.h"

/*
 * DSA_ERROR — error code alias.
 *
 * Reuses OPENSSL_RSA_FAILED (0x00000038) because no DSA-specific error code
 * has been defined in OpenSSLExceptionCodes.h.  All DSA exceptions thrown by
 * this file use this value so Java can distinguish them from success (0) but
 * cannot yet distinguish DSA errors from RSA errors at the Java level.
 */
static const int DSA_ERROR = OPENSSL_RSA_FAILED;

/*
 * dsaResult — cast a DSA* to the jlong handle returned to Java.
 *
 * The Java layer stores this opaque value and passes it back as keyId on
 * every subsequent native call.  The cast goes through intptr_t to remain
 * correct on both 32-bit and 64-bit platforms.
 *
 * @param dsa  OpenSSL DSA object (may be NULL on allocation failure).
 * @return     jlong handle; 0 if dsa is NULL.
 */
static jlong dsaResult(DSA *dsa)
{
    return (jlong)(intptr_t)dsa;
}

/*
 * getDSA — recover a DSA* from a jlong handle.
 *
 * Inverse of dsaResult().  Does not validate the pointer; callers check for
 * NULL before dereferencing.
 *
 * @param id  jlong handle previously returned by dsaResult().
 * @return    DSA* or NULL if id is 0.
 */
static DSA *getDSA(jlong id)
{
    return (DSA *)(intptr_t)id;
}

/*
 * getPKey — recover an EVP_PKEY* from a jlong handle.
 *
 * Used by signDigestCtx and verifyDigestCtx which receive an EVP_PKEY* that
 * wraps a DSA key (created earlier via DSAKEY_createPKey).
 *
 * @param id  jlong handle previously returned by DSAKEY_createPKey.
 * @return    EVP_PKEY* or NULL if id is 0.
 */
static EVP_PKEY *getPKey(jlong id)
{
    return (EVP_PKEY *)(intptr_t)id;
}

/*
 * encodeDSA — encode a DSA key to DER and return it as a Java byte[].
 *
 * Uses a three-step pattern:
 *   1. Size query: i2d_DSAPrivateKey / i2d_DSAPublicKey with NULL output
 *      pointer to determine the required buffer size.
 *   2. Allocate a Java byte[] of exactly that size.
 *   3. Pin the array, encode directly into the pinned buffer, then commit
 *      (ReleaseByteArrayElements with flag 0).
 *
 * This avoids allocating an intermediate OpenSSL heap buffer.
 *
 * @param env         JNI environment.
 * @param dsa         OpenSSL DSA object to encode.
 * @param privateKey  Non-zero to encode the private key; zero for public key.
 * @return            New Java byte[] containing the DER encoding, or NULL
 *                    with a pending exception on failure.
 */
static jbyteArray encodeDSA(JNIEnv *env, DSA *dsa, int privateKey)
{
    /* Step 1: determine encoded size without writing output */
    int size = privateKey ? i2d_DSAPrivateKey(dsa, NULL) : i2d_DSAPublicKey(dsa, NULL);
    if (size <= 0) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to determine DSA key encoding size");
        return NULL;
    }

    /* Step 2: allocate Java array */
    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) return NULL;  /* OutOfMemoryError already pending */

    /* Step 3: pin, encode in-place, commit */
    jbyte *bytes = (*env)->GetByteArrayElements(env, result, NULL);
    if (bytes == NULL) {
        (*env)->DeleteLocalRef(env, result);
        return NULL;
    }
    unsigned char *p = (unsigned char *)bytes;
    size = privateKey ? i2d_DSAPrivateKey(dsa, &p) : i2d_DSAPublicKey(dsa, &p);
    (*env)->ReleaseByteArrayElements(env, result, bytes, 0);  /* commit */

    if (size <= 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to encode DSA key");
        return NULL;
    }
    return result;
}

/*
 * encodeParameters — encode DSA domain parameters to DER and return as byte[].
 *
 * Uses the same three-step in-place encoding pattern as encodeDSA().
 * The DER structure is DSAparams ::= SEQUENCE { p INTEGER, q INTEGER, g INTEGER }
 * as defined in PKIX / ANSI X9.57.
 *
 * @param env  JNI environment.
 * @param dsa  OpenSSL DSA object whose parameters (p, q, g) are to be encoded.
 * @return     New Java byte[] containing the DER-encoded parameters, or NULL
 *             with a pending exception on failure.
 */
static jbyteArray encodeParameters(JNIEnv *env, DSA *dsa)
{
    int size = i2d_DSAparams(dsa, NULL);
    if (size <= 0) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to determine DSA parameter encoding size");
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) return NULL;
    jbyte *bytes = (*env)->GetByteArrayElements(env, result, NULL);
    if (bytes == NULL) {
        (*env)->DeleteLocalRef(env, result);
        return NULL;
    }
    unsigned char *p = (unsigned char *)bytes;
    size = i2d_DSAparams(dsa, &p);
    (*env)->ReleaseByteArrayElements(env, result, bytes, 0);
    if (size <= 0) {
        (*env)->DeleteLocalRef(env, result);
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to encode DSA parameters");
        return NULL;
    }
    return result;
}

/*
 * decodeDSA — parse a Java byte[] containing DER-encoded DSA key material.
 *
 * Pins the Java array, calls d2i_DSAPrivateKey or d2i_DSAPublicKey, then
 * unpins with JNI_ABORT (no write-back needed — the bytes are read-only).
 * The unpin happens before the NULL check so the pin is always released.
 *
 * @param env         JNI environment.
 * @param bytes       Java byte[] containing the DER-encoded key.
 * @param privateKey  Non-zero to parse as private key; zero for public key.
 * @return            Heap-allocated DSA* owned by the caller, or NULL with a
 *                    pending exception on parse failure.
 */
static DSA *decodeDSA(JNIEnv *env, jbyteArray bytes, int privateKey)
{
    if (bytes == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key bytes are null");
        return NULL;
    }
    jbyte *data = getByteArrayElementsSafe(env, bytes, "DSA decode", "Failed to access DSA key bytes");
    if (data == NULL) return NULL;
    const unsigned char *p = (const unsigned char *)data;
    long length = (*env)->GetArrayLength(env, bytes);
    DSA *dsa = privateKey ? d2i_DSAPrivateKey(NULL, &p, length)
                          : d2i_DSAPublicKey(NULL, &p, length);
    /* Unpin before checking result — cleanup must always happen */
    cleanupByteArray(env, bytes, data, JNI_ABORT);
    if (dsa == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to decode DSA key");
        logOpenSSLError(privateKey ? "d2i_DSAPrivateKey" : "d2i_DSAPublicKey");
    }
    return dsa;
}

/* =========================================================================
 * DSAKEY_generate(contextId, bits) -> jlong
 *
 * Generates a fresh DSA key pair (domain parameters + public/private key).
 * Two operations are performed in sequence:
 *   1. DSA_generate_parameters_ex: generates p, q, g for the requested bit
 *      size (FIPS 186-4 compliant sizes: 1024, 2048, 3072).
 *   2. DSA_generate_key: generates private key x and computes public key y.
 *
 * The returned DSA* handle is owned by the caller and must eventually be
 * freed via DSAKEY_delete.
 *
 * @param contextId  OpenSSL library context handle (unused; accepted for API
 *                   symmetry with other key types).
 * @param bits       Desired modulus (p) bit length.
 * @return           jlong DSA* handle, or 0 with a pending exception on failure.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1generate__JI(
        JNIEnv *env, jclass cls, jlong contextId, jint bits)
{
    DSA *dsa = DSA_new();
    if (dsa == NULL || DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL) != 1
            || DSA_generate_key(dsa) != 1) {
        if (dsa != NULL) DSA_free(dsa);
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key generation failed");
        logOpenSSLError("DSA_generate");
        return 0;
    }
    return dsaResult(dsa);
}

/* =========================================================================
 * DSAKEY_generateParameters(contextId, bits) -> byte[]
 *
 * Generates DSA domain parameters (p, q, g) only, without deriving a key
 * pair, and returns them as a DER-encoded DSAparams byte[].
 *
 * This is used by the Java DSAParameterGenerator SPI when the application
 * needs pre-generated parameters to share among multiple key pairs.
 *
 * The temporary DSA* is freed before returning; only the encoded parameters
 * byte[] is returned.
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param bits       Desired modulus bit length (1024 / 2048 / 3072).
 * @return           DER-encoded DSAparams byte[], or NULL with a pending
 *                   exception on failure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1generateParameters(
        JNIEnv *env, jclass cls, jlong contextId, jint bits)
{
    DSA *dsa = DSA_new();
    if (dsa == NULL || DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL) != 1) {
        if (dsa != NULL) DSA_free(dsa);
        setPendingOpenSSLException(env, DSA_ERROR, "DSA parameter generation failed");
        logOpenSSLError("DSA_generate_parameters_ex");
        return NULL;
    }
    jbyteArray result = encodeParameters(env, dsa);
    DSA_free(dsa);  /* parameters have been encoded; DSA* no longer needed */
    return result;
}

/* =========================================================================
 * DSAKEY_generate(contextId, parameterBytes[]) -> jlong
 *
 * Overload: generates a DSA key pair from caller-supplied DER-encoded domain
 * parameters (p, q, g).  Used when the application provides its own
 * DSAParameterSpec rather than generating new parameters.
 *
 * Steps:
 *   1. Parse parameterBytes with d2i_DSAparams — produces a DSA* containing
 *      p, q, g but no key material.
 *   2. Call DSA_generate_key to derive private key x and public key y.
 *
 * @param contextId      OpenSSL library context handle (unused).
 * @param parameterBytes DER-encoded DSAparams byte[].
 * @return               jlong DSA* handle, or 0 with a pending exception on failure.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1generate__J_3B(
        JNIEnv *env, jclass cls, jlong contextId, jbyteArray parameterBytes)
{
    if (parameterBytes == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA parameters are null");
        return 0;
    }
    jbyte *data = getByteArrayElementsSafe(env, parameterBytes, "DSA generate", "Failed to access DSA parameters");
    if (data == NULL) return 0;
    const unsigned char *p = (const unsigned char *)data;
    long length = (*env)->GetArrayLength(env, parameterBytes);
    DSA *dsa = d2i_DSAparams(NULL, &p, length);
    cleanupByteArray(env, parameterBytes, data, JNI_ABORT);
    if (dsa == NULL || DSA_generate_key(dsa) != 1) {
        if (dsa != NULL) DSA_free(dsa);
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key generation from parameters failed");
        logOpenSSLError("DSA_generate_key");
        return 0;
    }
    return dsaResult(dsa);
}

/* =========================================================================
 * DSAKEY_createPrivateKey(contextId, bytes[]) -> jlong
 *
 * Imports a DSA private key from a DER-encoded OpenSSL DSAPrivateKey
 * (SEQUENCE { version, p, q, g, y, x }) byte array.
 *
 * Delegates entirely to decodeDSA(env, bytes, 1).
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param bytes      DER-encoded DSAPrivateKey byte[].
 * @return           jlong DSA* handle, or 0 with a pending exception on failure.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1createPrivateKey(
        JNIEnv *env, jclass cls, jlong contextId, jbyteArray bytes)
{
    return dsaResult(decodeDSA(env, bytes, 1));
}

/* =========================================================================
 * DSAKEY_createPublicKey(contextId, bytes[]) -> jlong
 *
 * Imports a DSA public key from a DER-encoded OpenSSL DSAPublicKey
 * (INTEGER y wrapped in a DSAParams context) byte array.
 *
 * Delegates entirely to decodeDSA(env, bytes, 0).
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param bytes      DER-encoded DSAPublicKey byte[].
 * @return           jlong DSA* handle, or 0 with a pending exception on failure.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1createPublicKey(
        JNIEnv *env, jclass cls, jlong contextId, jbyteArray bytes)
{
    return dsaResult(decodeDSA(env, bytes, 0));
}

/* =========================================================================
 * DSAKEY_getParameters(contextId, keyId) -> byte[]
 *
 * Extracts and returns the domain parameters (p, q, g) from an existing DSA
 * key handle as a DER-encoded DSAparams byte[].
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param keyId      jlong DSA* handle.
 * @return           DER-encoded DSAparams byte[], or NULL with a pending
 *                   exception on failure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1getParameters(
        JNIEnv *env, jclass cls, jlong contextId, jlong keyId)
{
    DSA *dsa = getDSA(keyId);
    if (dsa == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key is null");
        return NULL;
    }
    return encodeParameters(env, dsa);
}

/* =========================================================================
 * DSAKEY_getPrivateKeyBytes(contextId, keyId) -> byte[]
 *
 * Serialises the private key to DER (OpenSSL DSAPrivateKey format:
 * SEQUENCE { version, p, q, g, y, x }).
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param keyId      jlong DSA* handle.
 * @return           DER-encoded DSAPrivateKey byte[], or NULL on failure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1getPrivateKeyBytes(
        JNIEnv *env, jclass cls, jlong contextId, jlong keyId)
{
    DSA *dsa = getDSA(keyId);
    if (dsa == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key is null");
        return NULL;
    }
    return encodeDSA(env, dsa, 1);
}

/* =========================================================================
 * DSAKEY_getPublicKeyBytes(contextId, keyId) -> byte[]
 *
 * Serialises the public key to DER (OpenSSL DSAPublicKey format).
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param keyId      jlong DSA* handle.
 * @return           DER-encoded DSAPublicKey byte[], or NULL on failure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1getPublicKeyBytes(
        JNIEnv *env, jclass cls, jlong contextId, jlong keyId)
{
    DSA *dsa = getDSA(keyId);
    if (dsa == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key is null");
        return NULL;
    }
    return encodeDSA(env, dsa, 0);
}

/* =========================================================================
 * DSAKEY_createPKey(contextId, keyId) -> jlong (EVP_PKEY*)
 *
 * Wraps an existing DSA* handle into a generic EVP_PKEY container.  This is
 * needed by the signature path (OpenSSLSignature.c) which operates on
 * EVP_PKEY* handles via EVP_DigestSign* / EVP_DigestVerify*.
 *
 * EVP_PKEY_set1_DSA copies a reference to the DSA object - the DSA* refcount
 * is incremented.  Both the original DSA* (keyId) and the new EVP_PKEY* must
 * be freed independently:
 *   - DSA* via DSAKEY_delete
 *   - EVP_PKEY* via RSAKEY_delete (or a dedicated EVP_PKEY delete if added)
 *
 * param contextId  OpenSSL library context handle (unused).
 * param keyId      jlong DSA* handle.
 * return           jlong EVP_PKEY* handle, or 0 with a pending exception
 *                  on failure.
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1createPKey(
        JNIEnv *env, jclass cls, jlong contextId, jlong keyId)
{
    DSA *dsa = getDSA(keyId);
    if (dsa == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA key is null");
        return 0;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_set1_DSA(pkey, dsa) != 1) {
        if (pkey != NULL) EVP_PKEY_free(pkey);
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to create DSA EVP_PKEY");
        logOpenSSLError("EVP_PKEY_set1_DSA");
        return 0;
    }
    return (jlong)(intptr_t)pkey;
}

/* =========================================================================
 * DSAKEY_delete(contextId, keyId)
 *
 * Frees the DSA* handle.  DSA_free decrements the DSA object's internal
 * reference count; the object is deallocated when the count reaches zero.
 * NULL-safe: DSA_free(NULL) is a no-op in OpenSSL.
 *
 * @param contextId  OpenSSL library context handle (unused).
 * @param keyId      jlong DSA* handle previously returned by a generate or
 *                   create function.
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1delete(
        JNIEnv *env, jclass cls, jlong contextId, jlong keyId)
{
    DSA_free(getDSA(keyId));
}

/*
 * signDigest — internal helper: sign a pre-computed digest with DSA.
 *
 * Allocates a C buffer sized by DSA_size(), calls DSA_sign(), copies the
 * result into a new Java byte[], and frees the C buffer.
 *
 * @param env           JNI environment.
 * @param digestNid     OpenSSL NID identifying the hash algorithm.  Pass
 *                      NID_undef when no DigestInfo wrapping is desired
 *                      (NONEwithDSA path).
 * @param digest        Pointer to the pre-computed hash bytes.
 * @param digestLength  Number of hash bytes.
 * @param dsa           DSA private key used for signing.
 * @return              New Java byte[] containing the DER-encoded DSA
 *                      signature (SEQUENCE { r INTEGER, s INTEGER }), or
 *                      NULL with a pending exception on failure.
 */
static jbyteArray signDigest(JNIEnv *env, int digestNid, const unsigned char *digest,
        unsigned int digestLength, DSA *dsa)
{
    /* DSA_size returns the maximum DER-encoded signature length in bytes */
    unsigned int signatureLength = (unsigned int)DSA_size(dsa);
    unsigned char *signature = (unsigned char *)malloc(signatureLength);
    if (signature == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to allocate DSA signature");
        return NULL;
    }
    if (DSA_sign(digestNid, digest, digestLength, signature, &signatureLength, dsa) != 1) {
        free(signature);
        setPendingOpenSSLException(env, DSA_ERROR, "DSA_sign failed");
        logOpenSSLError("DSA_sign");
        return NULL;
    }
    /* signatureLength now holds the actual (not maximum) encoded length */
    jbyteArray result = (*env)->NewByteArray(env, (jsize)signatureLength);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, (jsize)signatureLength, (jbyte *)signature);
    free(signature);
    return result;
}

/* =========================================================================
 * DSAKEY_signData(contextId, digestBytes[], keyId) -> byte[]
 *
 * Signs a pre-computed digest (NONEwithDSA path).  The Java layer has
 * already hashed the message; the raw hash bytes are passed here directly.
 *
 * NID_undef is passed to signDigest / DSA_sign so no additional DigestInfo
 * structure is prepended — the signature covers the raw hash bytes as-is.
 *
 * @param contextId   OpenSSL library context handle (unused).
 * @param digestBytes Java byte[] containing the pre-computed digest.
 * @param keyId       jlong DSA* private key handle.
 * @return            DER-encoded DSA signature byte[], or NULL with a pending
 *                    exception on failure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1signData(
        JNIEnv *env, jclass cls, jlong contextId, jbyteArray digestBytes, jlong keyId)
{
    if (digestBytes == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA digest is null");
        return NULL;
    }
    jbyte *digest = getByteArrayElementsSafe(env, digestBytes, "DSA sign", "Failed to access DSA digest");
    if (digest == NULL) return NULL;
    jsize length = (*env)->GetArrayLength(env, digestBytes);
    DSA *dsa = getDSA(keyId);
    jbyteArray result = dsa == NULL ? NULL : signDigest(env, NID_undef,
            (unsigned char *)digest, (unsigned int)length, dsa);
    cleanupByteArray(env, digestBytes, digest, JNI_ABORT);
    return result;
}

/* =========================================================================
 * DSAKEY_verifyData(contextId, digestBytes[], signatureBytes[], keyId) -> boolean
 *
 * Verifies a DSA signature against a pre-computed digest (NONEwithDSA path).
 *
 * Both arrays are pinned before the DSA_verify call and both are released
 * (with JNI_ABORT) after — even if the other pin fails — to prevent leaks.
 *
 * DSA_verify returns 1 (valid), 0 (invalid), or -1 (error).  Any non-1
 * result maps to JNI_FALSE; errors are not surfaced as exceptions here
 * because an invalid signature is a normal outcome.
 *
 * @param contextId      OpenSSL library context handle (unused).
 * @param digestBytes    Java byte[] containing the pre-computed digest.
 * @param signatureBytes Java byte[] containing the DER-encoded DSA signature.
 * @param keyId          jlong DSA* public key handle.
 * @return               JNI_TRUE if the signature is valid; JNI_FALSE otherwise.
 * =========================================================================*/
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1verifyData(
        JNIEnv *env, jclass cls, jlong contextId, jbyteArray digestBytes, jbyteArray signatureBytes, jlong keyId)
{
    if (digestBytes == NULL || signatureBytes == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA verification input is null");
        return JNI_FALSE;
    }
    jbyte *digest    = getByteArrayElementsSafe(env, digestBytes,    "DSA verify", "Failed to access DSA digest");
    jbyte *signature = getByteArrayElementsSafe(env, signatureBytes, "DSA verify", "Failed to access DSA signature");
    if (digest == NULL || signature == NULL) {
        if (digest    != NULL) cleanupByteArray(env, digestBytes,    digest,    JNI_ABORT);
        if (signature != NULL) cleanupByteArray(env, signatureBytes, signature, JNI_ABORT);
        return JNI_FALSE;
    }
    DSA *dsa = getDSA(keyId);
    int result = dsa == NULL ? -1 : DSA_verify(NID_undef, (unsigned char *)digest,
            (int)(*env)->GetArrayLength(env, digestBytes), (unsigned char *)signature,
            (int)(*env)->GetArrayLength(env, signatureBytes), dsa);
    cleanupByteArray(env, digestBytes,    digest,    JNI_ABORT);
    cleanupByteArray(env, signatureBytes, signature, JNI_ABORT);
    return result == 1 ? JNI_TRUE : JNI_FALSE;
}

/* =========================================================================
 * DSAKEY_signDigestCtx(contextId, digestCtxId, pkeyId) -> byte[]
 *
 * Finalises a live EVP_MD_CTX (SHA*withDSA path) and signs the resulting
 * digest.  Combines two operations that the Java streaming API performs in
 * sequence:
 *   1. EVP_DigestFinal_ex: writes the hash output into a stack buffer.
 *   2. signDigest: calls DSA_sign with the NID from the context.
 *
 * The EVP_PKEY* is used only to extract the inner DSA* via EVP_PKEY_get1_DSA
 * (which bumps the DSA refcount).  The caller must free the EVP_PKEY* handle
 * separately; this function frees the get1_ reference via DSA_free.
 *
 * @param contextId   OpenSSL library context handle (unused).
 * @param digestCtxId jlong EVP_MD_CTX* handle (live, not yet finalised).
 * @param pkeyId      jlong EVP_PKEY* handle wrapping a DSA private key.
 * @return            DER-encoded DSA signature byte[], or NULL with a pending
 *                    exception on failure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1signDigestCtx(
        JNIEnv *env, jclass cls, jlong contextId, jlong digestCtxId, jlong pkeyId)
{
    EVP_MD_CTX *digestContext = (EVP_MD_CTX *)(intptr_t)digestCtxId;
    EVP_PKEY   *pkey          = getPKey(pkeyId);
    if (digestContext == NULL || pkey == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA signature context is null");
        return NULL;
    }

    /* Finalise the digest into a stack-allocated buffer (max EVP_MAX_MD_SIZE = 64 bytes) */
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = sizeof(digest);
    if (EVP_DigestFinal_ex(digestContext, digest, &length) != 1) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to finalize DSA digest");
        return NULL;
    }

    /* Extract DSA* from EVP_PKEY* (bumps DSA refcount — must call DSA_free) */
    DSA *dsa = EVP_PKEY_get1_DSA(pkey);
    if (dsa == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to obtain DSA key");
        return NULL;
    }

    /* NID comes from the context — avoids length-to-NID ambiguity */
    int digestNid = EVP_MD_CTX_get_type(digestContext);
    jbyteArray result = signDigest(env, digestNid, digest, length, dsa);
    DSA_free(dsa);  /* release the get1_ reference */
    return result;
}

/* =========================================================================
 * DSAKEY_verifyDigestCtx(contextId, digestCtxId, signatureBytes[], signatureLength, pkeyId)
 *   -> boolean
 *
 * Finalises a live EVP_MD_CTX and verifies the DSA signature (SHA*withDSA path).
 *
 * The digest is finalised into a stack buffer before pinning the signature
 * array, so the hash is available even if pinning fails.
 *
 * DSA_verify returns 1 (valid), 0 (invalid), or -1 (error).  Any non-1
 * result maps to JNI_FALSE.
 *
 * @param contextId       OpenSSL library context handle (unused).
 * @param digestCtxId     jlong EVP_MD_CTX* handle (live, not yet finalised).
 * @param signatureBytes  Java byte[] containing the DER-encoded DSA signature.
 * @param signatureLength Number of valid bytes in signatureBytes to verify.
 * @param pkeyId          jlong EVP_PKEY* handle wrapping a DSA public key.
 * @return                JNI_TRUE if the signature is valid; JNI_FALSE otherwise.
 * =========================================================================*/
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DSAKEY_1verifyDigestCtx(
        JNIEnv *env, jclass cls, jlong contextId, jlong digestCtxId, jbyteArray signatureBytes,
        jint signatureLength, jlong pkeyId)
{
    EVP_MD_CTX *digestContext = (EVP_MD_CTX *)(intptr_t)digestCtxId;
    EVP_PKEY   *pkey          = getPKey(pkeyId);
    if (digestContext == NULL || pkey == NULL || signatureBytes == NULL) {
        setPendingOpenSSLException(env, DSA_ERROR, "DSA verification context is null");
        return JNI_FALSE;
    }

    /* Finalise digest before pinning the signature array */
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = sizeof(digest);
    if (EVP_DigestFinal_ex(digestContext, digest, &digestLength) != 1) {
        setPendingOpenSSLException(env, DSA_ERROR, "Failed to finalize DSA digest");
        return JNI_FALSE;
    }

    jbyte *signature = getByteArrayElementsSafe(env, signatureBytes, "DSA verify", "Failed to access DSA signature");
    if (signature == NULL) return JNI_FALSE;

    DSA *dsa = EVP_PKEY_get1_DSA(pkey);
    int digestNid = EVP_MD_CTX_get_type(digestContext);
    int result = dsa == NULL ? -1 : DSA_verify(digestNid, digest, (int)digestLength,
            (unsigned char *)signature, signatureLength, dsa);
    if (dsa != NULL) DSA_free(dsa);  /* release the get1_ reference */
    cleanupByteArray(env, signatureBytes, signature, JNI_ABORT);
    return result == 1 ? JNI_TRUE : JNI_FALSE;
}
