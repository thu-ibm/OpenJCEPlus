/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHKDF.h
 * @brief HKDF (HMAC-based Key Derivation Function) operations using OpenSSL.
 *
 * This header defines the interface for HKDF key derivation operations
 * as specified in RFC 5869. HKDF is a key derivation function that uses
 * HMAC to derive keys from input keying material.
 *
 * HKDF consists of two phases:
 * 1. Extract: Derives a pseudorandom key (PRK) from input keying material
 * 2. Expand: Expands the PRK into output keying material of desired length
 *
 * A combined derive operation performs both extract and expand in one call.
 *
 * Supported hash algorithms:
 * - SHA-256, SHA-384, SHA-512 (recommended)
 * - SHA-1 (legacy, not recommended)
 *
 * HKDF is widely used in modern cryptographic protocols including TLS 1.3,
 * Signal Protocol, and Noise Protocol Framework.
 */

#ifndef _OPENSSL_HKDF_H
#define _OPENSSL_HKDF_H

#include <jni.h>

/**
 * HKDF Extract: Derive a pseudorandom key (PRK) from input keying material.
 * This is the first step of the HKDF two-step process (RFC 5869).
 *
 * The extract step takes optional salt and input keying material (IKM) and
 * produces a fixed-length pseudorandom key suitable for use in the expand step.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param digestAlgo Digest algorithm name (e.g., "SHA-256", "SHA-384", "SHA-512")
 * @param salt Optional salt value (can be null or empty for default salt)
 * @param ikm Input keying material (the secret input)
 * @return Pseudorandom key (PRK) as byte array, or null on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HKDF_1extract(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo,
    jbyteArray salt, jbyteArray ikm);

/**
 * HKDF Expand: Expand a pseudorandom key into output keying material.
 * This is the second step of the HKDF two-step process (RFC 5869).
 *
 * The expand step takes a pseudorandom key (PRK) from the extract step,
 * optional context/application-specific info, and produces output keying
 * material of the desired length.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param digestAlgo Digest algorithm name (e.g., "SHA-256", "SHA-384", "SHA-512")
 * @param prk Pseudorandom key from extract step (must be at least hash length)
 * @param info Optional context and application-specific information (can be null or empty)
 * @param length Desired length of output keying material in bytes (must be <= 255 * hash_length)
 * @return Output keying material (OKM) as byte array of specified length, or null on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HKDF_1expand(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo,
    jbyteArray prk, jbyteArray info, jint length);

/**
 * HKDF Derive: Single-step key derivation combining extract and expand.
 * This is a convenience function that performs both HKDF steps in one call (RFC 5869).
 *
 * Equivalent to: expand(extract(salt, ikm), info, length)
 * Use this when you need to derive keys directly from input material without
 * needing the intermediate PRK.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param digestAlgo Digest algorithm name (e.g., "SHA-256", "SHA-384", "SHA-512")
 * @param salt Optional salt value (can be null or empty for default salt)
 * @param ikm Input keying material (the secret input)
 * @param info Optional context and application-specific information (can be null or empty)
 * @param length Desired length of output keying material in bytes (must be <= 255 * hash_length)
 * @return Output keying material (OKM) as byte array of specified length, or null on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_HKDF_1derive(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo,
    jbyteArray salt, jbyteArray ikm, jbyteArray info, jint length);

#endif 


