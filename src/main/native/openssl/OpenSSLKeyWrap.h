/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLKeyWrap.h
 * @brief AES Key Wrap (RFC 3394) and Key Wrap with Padding (RFC 5649).
 *
 * This header defines the interface for AES key wrapping operations.
 * Key wrapping is used to encrypt cryptographic keys for secure storage
 * or transmission using a Key Encryption Key (KEK).
 *
 * Supports two modes:
 * - RFC 3394: Standard AES Key Wrap (requires plaintext to be multiple of 8 bytes)
 * - RFC 5649: AES Key Wrap with Padding (supports any plaintext length)
 *
 * Key wrapping provides both confidentiality and integrity protection
 * for the wrapped key material.
 */

#ifndef _OPENSSL_KEYWRAP_H
#define _OPENSSL_KEYWRAP_H

#include <jni.h>

/**
 * Wrap (encrypt) a key using AES Key Wrap.
 *
 * Encrypts the plaintext key using the Key Encryption Key (KEK).
 * The output includes an integrity check value.
 *
 * @param env JNI environment pointer
 * @param thisObj Java class reference
 * @param fipsFlag FIPS mode flag (non-zero for FIPS mode)
 * @param plaintext The key material to wrap (must be multiple of 8 bytes if padding=false)
 * @param kek Key Encryption Key (AES-128, AES-192, or AES-256)
 * @param padding JNI_TRUE for RFC 5649 (with padding), JNI_FALSE for RFC 3394 (no padding)
 * @return Wrapped key as byte array, or NULL on error
 *
 * @throws OpenSSLException if wrapping fails or parameters are invalid
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    KEYWRAP_wrap
 * Signature: (J[B[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_KEYWRAP_1wrap(
    JNIEnv* env, jclass thisObj, jint fipsFlag, jbyteArray plaintext,
    jbyteArray kek, jboolean padding);

/**
 * Unwrap (decrypt) a key using AES Key Wrap.
 *
 * Decrypts the wrapped key using the Key Encryption Key (KEK).
 * Verifies the integrity check value during unwrapping.
 *
 * @param env JNI environment pointer
 * @param thisObj Java class reference
 * @param fipsFlag FIPS mode flag (non-zero for FIPS mode)
 * @param ciphertext The wrapped key to unwrap
 * @param kek Key Encryption Key (must match the key used for wrapping)
 * @param padding JNI_TRUE for RFC 5649 (with padding), JNI_FALSE for RFC 3394 (no padding)
 * @return Unwrapped key as byte array, or NULL on error
 *
 * @throws OpenSSLException if unwrapping fails, integrity check fails, or parameters are invalid
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    KEYWRAP_unwrap
 * Signature: (J[B[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_KEYWRAP_1unwrap(
    JNIEnv* env, jclass thisObj, jint fipsFlag, jbyteArray ciphertext,
    jbyteArray kek, jboolean padding);

#endif
