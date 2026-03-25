/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLPBKDF2.h
 * @brief PBKDF2 (Password-Based Key Derivation Function 2) operations using OpenSSL.
 *
 * This header defines the interface for PBKDF2 key derivation operations
 * as specified in RFC 8018 (PKCS #5 v2.1). PBKDF2 derives cryptographic
 * keys from passwords using a pseudorandom function (HMAC with a specified
 * hash algorithm).
 *
 * The function applies HMAC iteratively to increase computational cost,
 * making brute-force attacks more difficult. A random salt is used to
 * prevent rainbow table attacks.
 *
 * Security recommendations:
 * - Use strong hash algorithms (SHA-256 or better)
 * - Use random salts of at least 16 bytes
 * - Use high iteration counts (10,000+ minimum, 600,000+ recommended for SHA-256)
 * - Never reuse salts across different passwords
 *
 * PBKDF2 is widely used for password hashing and key derivation in
 * applications like disk encryption, password storage, and key wrapping.
 */

#ifndef _OPENSSL_PBKDF2_H
#define _OPENSSL_PBKDF2_H

#include <jni.h>

/**
 * PBKDF2 (Password-Based Key Derivation Function 2): Derive a key from a password.
 * Implements PBKDF2 as specified in RFC 8018 (PKCS #5 v2.1).
 *
 * PBKDF2 applies a pseudorandom function (HMAC with specified digest) to the password
 * along with a salt value and repeats the process many times to produce a derived key.
 * The iteration count increases the computational cost, making brute-force attacks more difficult.
 *
 * Security recommendations:
 * - Use a random salt of at least 16 bytes (128 bits)
 * - Use a minimum of 10,000 iterations (NIST recommends 10,000+, OWASP recommends 600,000+ for SHA-256)
 * - Use SHA-256 or stronger digest algorithms
 * - Never reuse salts across different passwords
 *
 * @param env JNI environment
 * @param cls Java class
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param digestAlgo Digest algorithm name for HMAC (e.g., "SHA-256", "SHA-384", "SHA-512")
 * @param password The password to derive the key from (user's secret)
 * @param salt Random salt value (should be unique per password, minimum 16 bytes recommended)
 * @param iterations Number of iterations (minimum 10,000 recommended, higher is more secure but slower)
 * @param keyLength Desired length of derived key in bytes
 * @return Derived key as byte array of specified length, or null on error
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_PBKDF2_1derive(
    JNIEnv* env, jclass cls, jint fipsFlag, jstring digestAlgo,
    jbyteArray password, jbyteArray salt, jint iterations, jint keyLength);

#endif 


