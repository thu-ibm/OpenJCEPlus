/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLRSAKey.c
 * @brief RSA key generation, import/export, cipher operations via OpenSSL EVP.
 *
 * All key handles are EVP_PKEY* stored as jlong.
 * Key format conventions (matching OCK / Java RSAKey):
 *   createPrivateKey  : PKCS#1 RSAPrivateKey DER with inline DER fallback for
 *                       plain n/e/d keys (RSAPrivateKeySpec, no CRT fields).
 *   createPublicKey   : PKCS#1 RSAPublicKey DER (SEQUENCE { n, e })
 *   getPrivateKeyBytes: PKCS#1 RSAPrivateKey DER (i2d_RSAPrivateKey)
 *   getPublicKeyBytes : PKCS#1 RSAPublicKey DER  (i2d_RSAPublicKey)
 *
 * Padding IDs (must match com.ibm.crypto.plus.provider.base.RSAPadding):
 *   0 = NoPadding, 1 = PKCS1Padding, 2 = OAEPPadding
 *
 * Digest IDs (must match RSAPadding.h):
 *   0=NONE 1=SHA1 2=SHA224 3=SHA256 4=SHA384 5=SHA512 6=SHA512/224 7=SHA512/256
 *
 * Implementation note — low-level RSA API retention:
 *   NoPadding/PKCS1 cipher ops and RSA sign/verify intentionally use the
 *   low-level RSA_public_encrypt / RSA_private_decrypt / RSA_sign / RSA_verify
 *   APIs (via EVP_PKEY_get1_RSA).  Reason:
 *   (a) RSAPrivateKeySpec keys carry only n, e, d (no CRT fields). OpenSSL 3's
 *       EVP_PKEY_decrypt refuses these keys; the low-level path uses raw
 *       m^d mod n and succeeds.
 *   (b) RSA_sign/RSA_verify handle DigestInfo wrapping transparently, matching
 *       the OCK behaviour expected by the Java layer.
 *   OAEP encrypt/decrypt uses EVP_PKEY_CTX (high-level) throughout since
 *   OAEP is never used with plain n/d-only keys, and uses EVP_MD_fetch so
 *   digest lookup respects the provider's OSSL_LIB_CTX (review item S-2).
 *   Key generation uses EVP_PKEY_CTX_new_from_name with the explicit libctx
 *   (review item A-4).
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

/* -------------------------------------------------------------------------
 * Padding / digest mapping helpers
 * -------------------------------------------------------------------------*/

/* Maps Java RSAPadding constant to OpenSSL RSA_PKCS1_* constant */
static int mapPadding(int rsaPaddingId)
{
    switch (rsaPaddingId) {
        case 0: return RSA_NO_PADDING;
        case 1: return RSA_PKCS1_PADDING;
        case 2: return RSA_PKCS1_OAEP_PADDING;
        default: return -1;
    }
}

/* Maps Java mdId to OpenSSL digest name string for EVP_MD_fetch.
 * Uses name strings rather than global EVP_sha*() handles so the lookup
 * respects the caller's OSSL_LIB_CTX (review item S-2). */
static const char* mdNameById(int mdId)
{
    switch (mdId) {
        case 1: return "SHA1";
        case 2: return "SHA2-224";
        case 3: return "SHA2-256";
        case 4: return "SHA2-384";
        case 5: return "SHA2-512";
        case 6: return "SHA2-512/224";
        case 7: return "SHA2-512/256";
        default: return "SHA1";   /* fallback */
    }
}

/* -------------------------------------------------------------------------
 * Set EVP_PKEY_CTX padding (for encrypt/decrypt)
 * Returns 1 on success, 0 on failure (exception set)
 * -------------------------------------------------------------------------*/
/* S-2 fix: pass libctx so EVP_MD_fetch resolves within the correct provider. */
static int setCtxPadding(JNIEnv* env, EVP_PKEY_CTX* ctx,
                          int rsaPaddingId, int mdId, int mgf1Id,
                          OSSL_LIB_CTX* libctx, const char* fn)
{
    int pad = mapPadding(rsaPaddingId);
    if (pad < 0) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "Unknown RSA padding id");
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_CTX_set_rsa_padding failed");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_padding");
        return 0;
    }
    if (pad == RSA_PKCS1_OAEP_PADDING) {
        EVP_MD* md  = EVP_MD_fetch(libctx, mdNameById(mdId),  NULL);
        EVP_MD* mgf = EVP_MD_fetch(libctx, mdNameById(mgf1Id), NULL);
        int ok = 1;
        if (md == NULL || mgf == NULL) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_MD_fetch failed for OAEP digest");
            ok = 0;
        }
        if (ok && EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_CTX_set_rsa_oaep_md failed");
            logOpenSSLError("EVP_PKEY_CTX_set_rsa_oaep_md");
            ok = 0;
        }
        if (!ok && md != NULL) EVP_MD_free(md);
        if (ok && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_CTX_set_rsa_mgf1_md failed");
            logOpenSSLError("EVP_PKEY_CTX_set_rsa_mgf1_md");
            ok = 0;
        }
        if (mgf != NULL) EVP_MD_free(mgf);
        if (!ok) return 0;
    }
    return 1;
}

/* =========================================================================
 * RSAKEY_generate(osslContextId, numBits, e) -> jlong
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1generate(
    JNIEnv* env, jclass cls, jlong osslContextId, jint numBits, jlong e)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_generate";
    logFunctionEntry(fn);

    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), fn, &context)) {
        logFunctionExit(fn);
        return 0;
    }

    /* A-4: use EVP_PKEY_CTX_new_from_name with explicit libctx */
    EVP_PKEY_CTX* ctx  = EVP_PKEY_CTX_new_from_name(context->libctx, "RSA", NULL);
    EVP_PKEY*     pkey = NULL;
    jlong         ret  = 0;

    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_CTX_new_from_name failed");
        logOpenSSLError("EVP_PKEY_CTX_new_from_name");
        goto done;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_keygen_init failed");
        logOpenSSLError("EVP_PKEY_keygen_init");
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)numBits) <= 0) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        logOpenSSLError("EVP_PKEY_CTX_set_rsa_keygen_bits");
        goto done;
    }
    {
        BIGNUM* bn_e = BN_new();
        if (bn_e == NULL || !BN_set_word(bn_e, (unsigned long)e)) {
            BN_free(bn_e);
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "BN_set_word for public exponent failed");
            goto done;
        }
        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn_e) <= 0) {
            BN_free(bn_e);
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_CTX_set1_rsa_keygen_pubexp failed");
            logOpenSSLError("EVP_PKEY_CTX_set1_rsa_keygen_pubexp");
            goto done;
        }
        BN_free(bn_e);
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0 || pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_keygen failed");
        logOpenSSLError("EVP_PKEY_keygen");
        goto done;
    }
    ret = (jlong)((intptr_t)pkey);

done:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey && ret == 0) EVP_PKEY_free(pkey);
    logFunctionExit(fn);
    return ret;
}

/* =========================================================================
 * RSAKEY_createPrivateKey(osslContextId, privateKeyBytes) -> jlong
 * Accepts PKCS#8 DER or traditional DER (d2i_PrivateKey auto-detects)
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1createPrivateKey(
    JNIEnv* env, jclass cls, jlong osslContextId, jbyteArray privateKeyBytes)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_createPrivateKey";
    logFunctionEntry(fn);

    if (privateKeyBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "privateKeyBytes is NULL");
        return 0;
    }

    jbyte* data = getByteArrayElementsSafe(env, privateKeyBytes, fn,
                                           "Failed to get private key bytes");
    if (data == NULL) return 0;

    jsize  len  = (*env)->GetArrayLength(env, privateKeyBytes);
    const unsigned char* p = (const unsigned char*)data;

    /* Parse PKCS#1 RSAPrivateKey DER.
     * Standard path: works for full CRT keys (n,e,d,p,q,dp,dq,qi all set).
     * OpenSSL 3 may reject keys where e=0 (non-CRT keys with only n,d).
     * In that case fall back to manual DER parsing: decode n and d, use
     * e=65537 as a placeholder, and build the key with RSA_set0_key(). */
    RSA* rsa = d2i_RSAPrivateKey(NULL, &p, (long)len);
    if (rsa == NULL) {
        /* Fallback: decode PKCS#1 SEQUENCE manually to extract n and d.
         * Layout: SEQUENCE { version, n, e, d, p, q, dp, dq, qi }
         * Helper macro to decode one DER INTEGER length field. */
        ERR_clear_error();

        /* Inline helper: read DER length at *cur, advance cur, return len */
        #define DER_READ_LEN(cur, out_len) do {                          \
            if (*(cur) & 0x80) {                                         \
                int _nb = *(cur)++ & 0x7f;                               \
                (out_len) = 0;                                           \
                for (int _i = 0; _i < _nb; _i++)                        \
                    (out_len) = ((out_len) << 8) | *(cur)++;             \
            } else { (out_len) = *(cur)++; }                            \
        } while (0)

        /* Inline helper: skip one DER TLV */
        #define DER_SKIP_TLV(cur) do {                                   \
            if (*(cur)++ != 0x02) goto fallback_fail;                   \
            int _l = 0; DER_READ_LEN(cur, _l); (cur) += _l;            \
        } while (0)

        const unsigned char* sp = (const unsigned char*)data;
        int ok = 0;
        BIGNUM* n_bn = NULL;
        BIGNUM* e_bn = NULL;
        BIGNUM* d_bn = NULL;

        /* SEQUENCE tag + length */
        if (*sp++ != 0x30) goto fallback_fail;
        { int seq_len = 0; DER_READ_LEN(sp, seq_len); (void)seq_len; }
        /* version INTEGER */
        DER_SKIP_TLV(sp);
        /* n (modulus) */
        if (*sp++ != 0x02) goto fallback_fail;
        { int nl = 0; DER_READ_LEN(sp, nl); n_bn = BN_bin2bn(sp, nl, NULL); sp += nl; }
        /* e (public exponent — may be 0, we ignore and use 65537) */
        DER_SKIP_TLV(sp);
        /* d (private exponent) */
        if (*sp++ != 0x02) goto fallback_fail;
        { int dl = 0; DER_READ_LEN(sp, dl); d_bn = BN_bin2bn(sp, dl, NULL); }

        e_bn = BN_new();
        if (n_bn && d_bn && e_bn && BN_set_word(e_bn, 65537UL)) {
            rsa = RSA_new();
            if (rsa && RSA_set0_key(rsa, n_bn, e_bn, d_bn) == 1) {
                ok = 1; /* n_bn/e_bn/d_bn owned by rsa now */
            } else {
                if (rsa) { RSA_free(rsa); rsa = NULL; }
            }
        }
        if (!ok) {
            BN_free(n_bn); BN_free(e_bn); BN_free(d_bn);
        }
        goto fallback_done;
        fallback_fail:;
        fallback_done:;
        #undef DER_READ_LEN
        #undef DER_SKIP_TLV

        if (rsa == NULL) {
            cleanupByteArray(env, privateKeyBytes, data, JNI_ABORT);
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "d2i_RSAPrivateKey failed");
            logOpenSSLError("d2i_RSAPrivateKey");
            logFunctionExit(fn);
            return 0;
        }
    } else {
        /* Standard parse succeeded; if CRT components are zero (non-CRT key),
         * rebuild the RSA object with only n, e, d so OpenSSL 3 uses the raw
         * m^d path.  RSA_set0_crt_params(NULL,NULL,NULL) does not clear
         * existing BIGNUMs, so we must create a fresh object. */
        const BIGNUM* p_bn = NULL;
        RSA_get0_factors(rsa, &p_bn, NULL);
        if (p_bn == NULL || BN_is_zero(p_bn)) {
            const BIGNUM* n_raw = NULL;
            const BIGNUM* e_raw = NULL;
            const BIGNUM* d_raw = NULL;
            RSA_get0_key(rsa, &n_raw, &e_raw, &d_raw);
            BIGNUM* n_cp = BN_dup(n_raw);
            BIGNUM* d_cp = BN_dup(d_raw);
            /* Use e=65537 if original e is zero */
            BIGNUM* e_cp = NULL;
            if (e_raw && !BN_is_zero(e_raw)) {
                e_cp = BN_dup(e_raw);
            } else {
                e_cp = BN_new();
                if (e_cp) BN_set_word(e_cp, 65537UL);
            }
            RSA* rsa2 = RSA_new();
            if (n_cp && e_cp && d_cp && rsa2 &&
                RSA_set0_key(rsa2, n_cp, e_cp, d_cp) == 1) {
                RSA_free(rsa);
                rsa = rsa2; /* rsa2 owns n_cp/e_cp/d_cp */
            } else {
                BN_free(n_cp); BN_free(e_cp); BN_free(d_cp);
                if (rsa2) RSA_free(rsa2);
                /* fall through with original rsa — may fail later */
            }
        }
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        if (pkey) EVP_PKEY_free(pkey);
        cleanupByteArray(env, privateKeyBytes, data, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_assign_RSA failed for private key");
        logFunctionExit(fn);
        return 0;
    }

    cleanupByteArray(env, privateKeyBytes, data, JNI_ABORT);
    logFunctionExit(fn);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * RSAKEY_createPublicKey(osslContextId, publicKeyBytes) -> jlong
 * Accepts SubjectPublicKeyInfo DER
 * =========================================================================*/
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1createPublicKey(
    JNIEnv* env, jclass cls, jlong osslContextId, jbyteArray publicKeyBytes)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_createPublicKey";
    logFunctionEntry(fn);

    if (publicKeyBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "publicKeyBytes is NULL");
        return 0;
    }

    jbyte* data = getByteArrayElementsSafe(env, publicKeyBytes, fn,
                                           "Failed to get public key bytes");
    if (data == NULL) return 0;

    jsize  len  = (*env)->GetArrayLength(env, publicKeyBytes);
    const unsigned char* p = (const unsigned char*)data;

    /* Accept PKCS#1 RSAPublicKey DER */
    RSA* rsa = d2i_RSAPublicKey(NULL, &p, (long)len);
    if (rsa == NULL) {
        cleanupByteArray(env, publicKeyBytes, data, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "d2i_RSAPublicKey failed");
        logOpenSSLError("d2i_RSAPublicKey");
        logFunctionExit(fn);
        return 0;
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        if (pkey) EVP_PKEY_free(pkey);
        cleanupByteArray(env, publicKeyBytes, data, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_assign_RSA failed for public key");
        logFunctionExit(fn);
        return 0;
    }

    cleanupByteArray(env, publicKeyBytes, data, JNI_ABORT);
    logFunctionExit(fn);
    return (jlong)((intptr_t)pkey);
}

/* =========================================================================
 * RSAKEY_getPrivateKeyBytes(osslContextId, rsaKeyId) -> byte[]
 * Returns traditional PKCS#1 / PKCS#8 DER (i2d_PrivateKey)
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1getPrivateKeyBytes(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_getPrivateKeyBytes";
    logFunctionEntry(fn);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "RSA key handle is NULL");
        logFunctionExit(fn);
        return NULL;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed (getPrivateKeyBytes)");
        logFunctionExit(fn);
        return NULL;
    }
    unsigned char* der = NULL;
    int len = i2d_RSAPrivateKey(rsa, &der);
    RSA_free(rsa);
    if (len <= 0 || der == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "i2d_RSAPrivateKey failed");
        logOpenSSLError("i2d_RSAPrivateKey");
        logFunctionExit(fn);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, len);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, len, (jbyte*)der);
    }
    OPENSSL_free(der);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSAKEY_getPublicKeyBytes(osslContextId, rsaKeyId) -> byte[]
 * Returns SubjectPublicKeyInfo DER (i2d_PUBKEY)
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1getPublicKeyBytes(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_getPublicKeyBytes";
    logFunctionEntry(fn);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaKeyId);
    if (pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "RSA key handle is NULL");
        logFunctionExit(fn);
        return NULL;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed (getPublicKeyBytes)");
        logFunctionExit(fn);
        return NULL;
    }
    unsigned char* der = NULL;
    int len = i2d_RSAPublicKey(rsa, &der);
    RSA_free(rsa);
    if (len <= 0 || der == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "i2d_RSAPublicKey failed");
        logOpenSSLError("i2d_RSAPublicKey");
        logFunctionExit(fn);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, len);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, len, (jbyte*)der);
    }
    OPENSSL_free(der);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSAKEY_size(osslContextId, rsaKeyId) -> int   (modulus bytes)
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1size(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId)
{
    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaKeyId);
    if (pkey == NULL) return 0;
    return (jint)EVP_PKEY_get_size(pkey);
}

/* =========================================================================
 * RSAKEY_delete(osslContextId, rsaKeyId)
 * =========================================================================*/
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1delete(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId)
{
    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaKeyId);
    if (pkey != NULL) EVP_PKEY_free(pkey);
}

/* =========================================================================
 * RSACIPHER_public_encrypt
 * (osslContextId, rsaKeyId, rsaPaddingId, mdId, mgf1Id,
 *  plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset)
 * -> int (output length)
 *
 * OAEP uses EVP_PKEY_CTX (high-level).
 * NoPadding / PKCS1 use RSA_public_encrypt (low-level) for OpenSSL 3 compat.
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSACIPHER_1public_1encrypt(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId,
    jint rsaPaddingId, jint mdId, jint mgf1Id,
    jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
    jbyteArray ciphertext, jint ciphertextOffset)
{
    static const char* fn = "OpenSSLNativeInterface.RSACIPHER_public_encrypt";
    logFunctionEntry(fn);

    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), fn, &context)) {
        logFunctionExit(fn);
        return 0;
    }

    EVP_PKEY* pkey   = (EVP_PKEY*)((intptr_t)rsaKeyId);
    jbyte*    ptNat  = NULL;
    jbyte*    ctNat  = NULL;
    jint      result = 0;

    if (pkey == NULL || plaintext == NULL || ciphertext == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to public_encrypt");
        goto done;
    }

    ptNat = getByteArrayElementsSafe(env, plaintext, fn, "get plaintext");
    ctNat = getByteArrayElementsSafe(env, ciphertext, fn, "get ciphertext");
    if (ptNat == NULL || ctNat == NULL) goto done;

    if ((int)rsaPaddingId == 2) {
        /* OAEP — use EVP_PKEY_CTX high-level API with explicit libctx */
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(context->libctx, pkey, NULL);
        if (ctx == NULL || EVP_PKEY_encrypt_init(ctx) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_encrypt_init failed (OAEP)");
            logOpenSSLError("EVP_PKEY_encrypt_init");
            if (ctx) EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        if (!setCtxPadding(env, ctx, (int)rsaPaddingId, (int)mdId, (int)mgf1Id, context->libctx, fn)) {
            EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, NULL, &outLen,
                             (unsigned char*)ptNat + plaintextOffset,
                             (size_t)plaintextLen) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_encrypt size-query failed (OAEP)");
            logOpenSSLError("EVP_PKEY_encrypt");
            EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        if (EVP_PKEY_encrypt(ctx, (unsigned char*)ctNat + ciphertextOffset, &outLen,
                             (unsigned char*)ptNat + plaintextOffset,
                             (size_t)plaintextLen) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_encrypt failed (OAEP)");
            logOpenSSLError("EVP_PKEY_encrypt");
            EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        EVP_PKEY_CTX_free(ctx);
        result = (jint)outLen;
    } else {
        /* NoPadding / PKCS1 — use RSA_public_encrypt (low-level) */
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_get1_RSA failed (public_encrypt)");
            goto done;
        }
        int pad = mapPadding((int)rsaPaddingId);
        int r = RSA_public_encrypt((int)plaintextLen,
                                   (unsigned char*)ptNat + plaintextOffset,
                                   (unsigned char*)ctNat + ciphertextOffset,
                                   rsa, pad);
        RSA_free(rsa);
        if (r < 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "RSA_public_encrypt failed");
            logOpenSSLError("RSA_public_encrypt");
            goto done;
        }
        result = (jint)r;
    }

done:
    if (ptNat) cleanupByteArray(env, plaintext, ptNat, JNI_ABORT);
    if (ctNat) cleanupByteArray(env, ciphertext, ctNat, 0);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSACIPHER_private_encrypt  (NONEwithRSA / RSAforSSL sign path)
 * Uses RSA_private_encrypt (raw PKCS#1 with NoPadding or PKCS1)
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSACIPHER_1private_1encrypt(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId,
    jint rsaPaddingId,
    jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
    jbyteArray ciphertext, jint ciphertextOffset, jboolean convertKey)
{
    static const char* fn = "OpenSSLNativeInterface.RSACIPHER_private_encrypt";
    logFunctionEntry(fn);

    EVP_PKEY* pkey   = (EVP_PKEY*)((intptr_t)rsaKeyId);
    jbyte*    ptNat  = NULL;
    jbyte*    ctNat  = NULL;
    jint      result = 0;

    if (pkey == NULL || plaintext == NULL || ciphertext == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to private_encrypt");
        goto done;
    }

    ptNat = getByteArrayElementsSafe(env, plaintext, fn, "get plaintext");
    ctNat = getByteArrayElementsSafe(env, ciphertext, fn, "get ciphertext");
    if (ptNat == NULL || ctNat == NULL) goto done;

    {
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_get1_RSA failed");
            goto done;
        }
        int pad = mapPadding((int)rsaPaddingId);
        int r = RSA_private_encrypt((int)plaintextLen,
                                    (unsigned char*)ptNat + plaintextOffset,
                                    (unsigned char*)ctNat + ciphertextOffset,
                                    rsa, pad);
        RSA_free(rsa);
        if (r < 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "RSA_private_encrypt failed");
            logOpenSSLError("RSA_private_encrypt");
            goto done;
        }
        result = (jint)r;
    }

done:
    if (ptNat) cleanupByteArray(env, plaintext, ptNat, JNI_ABORT);
    if (ctNat) cleanupByteArray(env, ciphertext, ctNat, 0);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSACIPHER_public_decrypt  (NONEwithRSA / RSAforSSL verify path)
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSACIPHER_1public_1decrypt(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId,
    jint rsaPaddingId,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
    jbyteArray plaintext, jint plaintextOffset)
{
    static const char* fn = "OpenSSLNativeInterface.RSACIPHER_public_decrypt";
    logFunctionEntry(fn);

    EVP_PKEY* pkey   = (EVP_PKEY*)((intptr_t)rsaKeyId);
    jbyte*    ptNat  = NULL;
    jbyte*    ctNat  = NULL;
    jint      result = 0;

    if (pkey == NULL || plaintext == NULL || ciphertext == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to public_decrypt");
        goto done;
    }

    ptNat = getByteArrayElementsSafe(env, plaintext, fn, "get plaintext");
    ctNat = getByteArrayElementsSafe(env, ciphertext, fn, "get ciphertext");
    if (ptNat == NULL || ctNat == NULL) goto done;

    {
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_get1_RSA failed");
            goto done;
        }
        int pad = mapPadding((int)rsaPaddingId);
        int r = RSA_public_decrypt((int)ciphertextLen,
                                   (unsigned char*)ctNat + ciphertextOffset,
                                   (unsigned char*)ptNat + plaintextOffset,
                                   rsa, pad);
        RSA_free(rsa);
        if (r < 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "RSA_public_decrypt failed");
            logOpenSSLError("RSA_public_decrypt");
            goto done;
        }
        result = (jint)r;
    }

done:
    if (ptNat) cleanupByteArray(env, plaintext, ptNat, 0);
    if (ctNat) cleanupByteArray(env, ciphertext, ctNat, JNI_ABORT);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSACIPHER_private_decrypt
 * OAEP uses EVP_PKEY_CTX (high-level).
 * NoPadding / PKCS1 use RSA_private_decrypt (low-level) for OpenSSL 3 compat.
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSACIPHER_1private_1decrypt(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong rsaKeyId,
    jint rsaPaddingId, jint mdId, jint mgf1Id,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
    jbyteArray plaintext, jint plaintextOffset, jboolean convertKey)
{
    static const char* fn = "OpenSSLNativeInterface.RSACIPHER_private_decrypt";
    logFunctionEntry(fn);

    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), fn, &context)) {
        logFunctionExit(fn);
        return 0;
    }

    EVP_PKEY* pkey   = (EVP_PKEY*)((intptr_t)rsaKeyId);
    jbyte*    ptNat  = NULL;
    jbyte*    ctNat  = NULL;
    jint      result = 0;

    if (pkey == NULL || plaintext == NULL || ciphertext == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to private_decrypt");
        goto done;
    }

    ptNat = getByteArrayElementsSafe(env, plaintext, fn, "get plaintext");
    ctNat = getByteArrayElementsSafe(env, ciphertext, fn, "get ciphertext");
    if (ptNat == NULL || ctNat == NULL) goto done;

    if ((int)rsaPaddingId == 2) {
        /* OAEP — use EVP_PKEY_CTX high-level API with explicit libctx */
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(context->libctx, pkey, NULL);
        if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_decrypt_init failed (OAEP)");
            logOpenSSLError("EVP_PKEY_decrypt_init");
            if (ctx) EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        if (!setCtxPadding(env, ctx, (int)rsaPaddingId, (int)mdId, (int)mgf1Id, context->libctx, fn)) {
            EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, NULL, &outLen,
                             (unsigned char*)ctNat + ciphertextOffset,
                             (size_t)ciphertextLen) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_decrypt size-query failed (OAEP)");
            logOpenSSLError("EVP_PKEY_decrypt");
            EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        if (EVP_PKEY_decrypt(ctx, (unsigned char*)ptNat + plaintextOffset, &outLen,
                             (unsigned char*)ctNat + ciphertextOffset,
                             (size_t)ciphertextLen) <= 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_decrypt failed (OAEP)");
            logOpenSSLError("EVP_PKEY_decrypt");
            EVP_PKEY_CTX_free(ctx);
            goto done;
        }
        EVP_PKEY_CTX_free(ctx);
        result = (jint)outLen;
    } else {
        /* NoPadding / PKCS1 — use RSA_private_decrypt (low-level) */
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "EVP_PKEY_get1_RSA failed (private_decrypt)");
            goto done;
        }
        int pad = mapPadding((int)rsaPaddingId);
        int r = RSA_private_decrypt((int)ciphertextLen,
                                    (unsigned char*)ctNat + ciphertextOffset,
                                    (unsigned char*)ptNat + plaintextOffset,
                                    rsa, pad);
        RSA_free(rsa);
        if (r < 0) {
            setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                       "RSA_private_decrypt failed");
            logOpenSSLError("RSA_private_decrypt");
            goto done;
        }
        result = (jint)r;
    }

done:
    if (ptNat) cleanupByteArray(env, plaintext, ptNat, 0);
    if (ctNat) cleanupByteArray(env, ciphertext, ctNat, JNI_ABORT);
    logFunctionExit(fn);
    return result;
}

/* -------------------------------------------------------------------------
 * Map digest length to OpenSSL NID for RSA_sign / RSA_verify.
 * Supports SHA-1 (20), SHA-224 (28), SHA-256 (32), SHA-384 (48), SHA-512 (64),
 * SHA-512/224 (28), SHA-512/256 (32) and SHA3 variants (same lengths).
 * When ambiguous (28, 32) we default to the common SHA-2 variant.
 * For NONEwithRSA the caller passes 0 as digestLen.
 * -------------------------------------------------------------------------*/
static int digestLenToNid(int digestLen)
{
    switch (digestLen) {
        case 20: return NID_sha1;
        case 28: return NID_sha224;
        case 32: return NID_sha256;
        case 48: return NID_sha384;
        case 64: return NID_sha512;
        default: return NID_sha256; /* safe fallback */
    }
}

/* =========================================================================
 * RSAKEY_signDataWithRSA(osslContextId, digestBytes, digestBytesLen, rsaPrivKeyId) -> byte[]
 * Signs a pre-computed digest with proper DigestInfo wrapping (SHA*withRSA).
 * Uses RSA_sign which wraps the hash in a DigestInfo structure.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1signDataWithRSA(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jbyteArray digestBytes, jint digestBytesLen, jlong rsaPrivKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_signDataWithRSA";
    logFunctionEntry(fn);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaPrivKeyId);
    if (pkey == NULL || digestBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to RSAKEY_signDataWithRSA");
        return NULL;
    }

    jbyte* digestNat = getByteArrayElementsSafe(env, digestBytes, fn,
                                                "Failed to get digest bytes");
    if (digestNat == NULL) return NULL;

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        cleanupByteArray(env, digestBytes, digestNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed for signDataWithRSA");
        logFunctionExit(fn);
        return NULL;
    }

    int sigLen = RSA_size(rsa);
    unsigned char* sig = (unsigned char*)malloc(sigLen);
    if (sig == NULL) {
        RSA_free(rsa);
        cleanupByteArray(env, digestBytes, digestNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "malloc failed for RSA signature buffer");
        logFunctionExit(fn);
        return NULL;
    }

    int nid = digestLenToNid((int)digestBytesLen);
    unsigned int outLen = (unsigned int)sigLen;
    int r = RSA_sign(nid, (unsigned char*)digestNat, (unsigned int)digestBytesLen,
                     sig, &outLen, rsa);
    RSA_free(rsa);
    cleanupByteArray(env, digestBytes, digestNat, JNI_ABORT);

    if (r != 1) {
        free(sig);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "RSA_sign failed");
        logOpenSSLError("RSA_sign");
        logFunctionExit(fn);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outLen, (jbyte*)sig);
    }
    free(sig);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSAKEY_verifyDataWithRSA(osslContextId, digestBytes, digestBytesLen,
 *                           sigBytes, sigBytesLen, rsaPubKeyId) -> boolean
 * Verifies a PKCS#1 v1.5 RSA signature against a pre-computed digest.
 * Uses RSA_verify which handles DigestInfo unwrapping.
 * =========================================================================*/
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1verifyDataWithRSA(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jbyteArray digestBytes, jint digestBytesLen,
    jbyteArray sigBytes, jint sigBytesLen, jlong rsaPubKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_verifyDataWithRSA";
    logFunctionEntry(fn);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaPubKeyId);
    if (pkey == NULL || digestBytes == NULL || sigBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to RSAKEY_verifyDataWithRSA");
        return JNI_FALSE;
    }

    jbyte* digestNat = getByteArrayElementsSafe(env, digestBytes, fn,
                                                "Failed to get digest bytes");
    if (digestNat == NULL) return JNI_FALSE;

    jbyte* sigNat = getByteArrayElementsSafe(env, sigBytes, fn,
                                             "Failed to get sig bytes");
    if (sigNat == NULL) {
        cleanupByteArray(env, digestBytes, digestNat, JNI_ABORT);
        return JNI_FALSE;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        cleanupByteArray(env, digestBytes, digestNat, JNI_ABORT);
        cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed for verifyDataWithRSA");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    int nid = digestLenToNid((int)digestBytesLen);
    int r = RSA_verify(nid, (unsigned char*)digestNat, (unsigned int)digestBytesLen,
                       (unsigned char*)sigNat, (unsigned int)sigBytesLen, rsa);
    RSA_free(rsa);
    cleanupByteArray(env, digestBytes, digestNat, JNI_ABORT);
    cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);

    logFunctionExit(fn);
    return (r == 1) ? JNI_TRUE : JNI_FALSE;
}

/* =========================================================================
 * PKEY_getBaseId(osslContextId, pkeyId) -> int
 * Returns EVP_PKEY_base_id(pkey): EVP_PKEY_RSA=6, EVP_PKEY_EC=408, etc.
 * =========================================================================*/
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_PKEY_1getBaseId(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong pkeyId)
{
    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)pkeyId);
    if (pkey == NULL) return -1;
    return (jint)EVP_PKEY_get_base_id(pkey);
}


/* =========================================================================
 * RSAKEY_signDigestCtx(osslContextId, digestCtxId, rsaPrivKeyId) -> byte[]
 * Finalizes the digest context, then signs with proper DigestInfo wrapping.
 * The MD NID is obtained directly from the live digest context.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1signDigestCtx(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong digestCtxId, jlong rsaPrivKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_signDigestCtx";
    logFunctionEntry(fn);

    EVP_MD_CTX* mdCtx = (EVP_MD_CTX*)((intptr_t)digestCtxId);
    EVP_PKEY*   pkey  = (EVP_PKEY*)((intptr_t)rsaPrivKeyId);

    if (mdCtx == NULL || pkey == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to RSAKEY_signDigestCtx");
        return NULL;
    }

    /* Get digest NID and output size from the live context */
    int nid = EVP_MD_CTX_get_type(mdCtx);
    unsigned int hashLen = (unsigned int)EVP_MD_CTX_get_size(mdCtx);
    if (nid == NID_undef || hashLen == 0) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "Failed to get digest NID or size from context");
        logFunctionExit(fn);
        return NULL;
    }

    /* Finalize the digest */
    unsigned char hash[EVP_MAX_MD_SIZE];
    if (EVP_DigestFinal_ex(mdCtx, hash, &hashLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                   "EVP_DigestFinal_ex failed in signDigestCtx");
        logOpenSSLError("EVP_DigestFinal_ex");
        logFunctionExit(fn);
        return NULL;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed in signDigestCtx");
        logFunctionExit(fn);
        return NULL;
    }

    int sigLen = RSA_size(rsa);
    unsigned char* sig = (unsigned char*)malloc(sigLen);
    if (sig == NULL) {
        RSA_free(rsa);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "malloc failed for RSA signature buffer in signDigestCtx");
        logFunctionExit(fn);
        return NULL;
    }

    unsigned int outLen = (unsigned int)sigLen;
    int r = RSA_sign(nid, hash, hashLen, sig, &outLen, rsa);
    RSA_free(rsa);

    jbyteArray result = NULL;
    if (r != 1) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED, "RSA_sign failed");
        logOpenSSLError("RSA_sign");
    } else {
        result = (*env)->NewByteArray(env, (jsize)outLen);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, (jsize)outLen, (jbyte*)sig);
        }
    }
    free(sig);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSAKEY_verifyDigestCtx(osslContextId, digestCtxId, sigBytes, sigBytesLen, rsaPubKeyId) -> boolean
 * Finalizes the digest context, then verifies the RSA PKCS#1 signature.
 * =========================================================================*/
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSAKEY_1verifyDigestCtx(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jlong digestCtxId, jbyteArray sigBytes, jint sigBytesLen, jlong rsaPubKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSAKEY_verifyDigestCtx";
    logFunctionEntry(fn);

    EVP_MD_CTX* mdCtx = (EVP_MD_CTX*)((intptr_t)digestCtxId);
    EVP_PKEY*   pkey  = (EVP_PKEY*)((intptr_t)rsaPubKeyId);

    if (mdCtx == NULL || pkey == NULL || sigBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to RSAKEY_verifyDigestCtx");
        return JNI_FALSE;
    }

    int nid = EVP_MD_CTX_get_type(mdCtx);
    unsigned int hashLen = (unsigned int)EVP_MD_CTX_get_size(mdCtx);
    if (nid == NID_undef || hashLen == 0) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "Failed to get digest NID or size from context");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    if (EVP_DigestFinal_ex(mdCtx, hash, &hashLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_DIGEST_FINAL_FAILED,
                                   "EVP_DigestFinal_ex failed in verifyDigestCtx");
        logOpenSSLError("EVP_DigestFinal_ex");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    jbyte* sigNat = getByteArrayElementsSafe(env, sigBytes, fn, "Failed to get sig bytes");
    if (sigNat == NULL) return JNI_FALSE;

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed in verifyDigestCtx");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    int r = RSA_verify(nid, hash, hashLen,
                       (unsigned char*)sigNat, (unsigned int)sigBytesLen, rsa);
    RSA_free(rsa);
    cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);
    logFunctionExit(fn);
    return (r == 1) ? JNI_TRUE : JNI_FALSE;
}


/* =========================================================================
 * RSASSL_SIGNATURE_sign(osslContextId, digest, rsaKeyId) -> byte[]
 *
 * Signs a pre-computed 36-byte MD5+SHA-1 combined digest (SSL legacy).
 * Uses RSA_sign with NID_md5_sha1, which matches ICC_RSA_sign on OCK.
 * rsaKeyId is an EVP_PKEY* (RSA private key) stored as jlong.
 * =========================================================================*/
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSASSL_1SIGNATURE_1sign(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jbyteArray digest, jlong rsaKeyId)
{
    static const char* fn = "OpenSSLNativeInterface.RSASSL_SIGNATURE_sign";
    logFunctionEntry(fn);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaKeyId);
    if (pkey == NULL || digest == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to RSASSL_SIGNATURE_sign");
        logFunctionExit(fn);
        return NULL;
    }

    jbyte* digestNat = getByteArrayElementsSafe(env, digest, fn, "Failed to get digest bytes");
    if (digestNat == NULL) { logFunctionExit(fn); return NULL; }
    jsize digestLen = (*env)->GetArrayLength(env, digest);

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        cleanupByteArray(env, digest, digestNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed in RSASSL_SIGNATURE_sign");
        logFunctionExit(fn);
        return NULL;
    }

    int sigLen = RSA_size(rsa);
    unsigned char* sigBuf = (unsigned char*)malloc((size_t)sigLen);
    if (sigBuf == NULL) {
        RSA_free(rsa);
        cleanupByteArray(env, digest, digestNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                                   "malloc failed in RSASSL_SIGNATURE_sign");
        logFunctionExit(fn);
        return NULL;
    }

    unsigned int outLen = (unsigned int)sigLen;
    int rc = RSA_sign(NID_md5_sha1,
                      (unsigned char*)digestNat, (unsigned int)digestLen,
                      sigBuf, &outLen, rsa);
    RSA_free(rsa);
    cleanupByteArray(env, digest, digestNat, JNI_ABORT);

    if (rc != 1) {
        free(sigBuf);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "RSA_sign failed in RSASSL_SIGNATURE_sign");
        logOpenSSLError("RSA_sign");
        logFunctionExit(fn);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outLen, (jbyte*)sigBuf);
    }
    free(sigBuf);
    logFunctionExit(fn);
    return result;
}

/* =========================================================================
 * RSASSL_SIGNATURE_verify(osslContextId, digest, rsaKeyId, sigBytes, convert)
 *   -> boolean
 *
 * Verifies the legacy MD5+SHA-1 SSL RSA signature.
 * rsaKeyId is an EVP_PKEY* (RSA public key) stored as jlong.
 * convert is reserved for future encoding fixup (ignored here; OpenSSL
 * RSA keys loaded from DER are always normalised).
 * =========================================================================*/
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RSASSL_1SIGNATURE_1verify(
    JNIEnv* env, jclass cls, jlong osslContextId,
    jbyteArray digest, jlong rsaKeyId, jbyteArray sigBytes, jboolean convert)
{
    static const char* fn = "OpenSSLNativeInterface.RSASSL_SIGNATURE_verify";
    logFunctionEntry(fn);

    EVP_PKEY* pkey = (EVP_PKEY*)((intptr_t)rsaKeyId);
    if (pkey == NULL || digest == NULL || sigBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "NULL argument to RSASSL_SIGNATURE_verify");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    jbyte* digestNat = getByteArrayElementsSafe(env, digest, fn, "Failed to get digest bytes");
    if (digestNat == NULL) { logFunctionExit(fn); return JNI_FALSE; }
    jsize digestLen = (*env)->GetArrayLength(env, digest);

    jbyte* sigNat = getByteArrayElementsSafe(env, sigBytes, fn, "Failed to get sig bytes");
    if (sigNat == NULL) {
        cleanupByteArray(env, digest, digestNat, JNI_ABORT);
        logFunctionExit(fn);
        return JNI_FALSE;
    }
    jsize sigLen = (*env)->GetArrayLength(env, sigBytes);

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        cleanupByteArray(env, digest, digestNat, JNI_ABORT);
        cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_RSA_FAILED,
                                   "EVP_PKEY_get1_RSA failed in RSASSL_SIGNATURE_verify");
        logFunctionExit(fn);
        return JNI_FALSE;
    }

    int rc = RSA_verify(NID_md5_sha1,
                        (unsigned char*)digestNat, (unsigned int)digestLen,
                        (unsigned char*)sigNat, (unsigned int)sigLen, rsa);
    RSA_free(rsa);
    cleanupByteArray(env, digest, digestNat, JNI_ABORT);
    cleanupByteArray(env, sigBytes, sigNat, JNI_ABORT);

    logFunctionExit(fn);
    return (rc == 1) ? JNI_TRUE : JNI_FALSE;
}
