/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLCCM.h
 * @brief CCM (Counter with CBC-MAC) mode cipher operations using OpenSSL.
 *
 * This header defines the interface for AES-CCM authenticated encryption
 * operations. CCM mode provides both confidentiality and authenticity,
 * combining counter mode encryption with CBC-MAC authentication.
 *
 * CCM is particularly useful in constrained environments and is specified
 * in NIST SP 800-38C and RFC 3610.
 */

#ifndef _OPENSSL_CCM_H
#define _OPENSSL_CCM_H

#include <jni.h>

/**
 * @defgroup CCM_Constants CCM Mode Constants
 * @{
 */

/** Maximum authentication tag size in bytes (128 bits) */
#define MAX_CCM_TAG_SIZE 16

/** Minimum authentication tag size in bytes (32 bits) */
#define MIN_CCM_TAG_SIZE 4

/** Maximum initialization vector (nonce) size in bytes */
#define MAX_CCM_IV_SIZE 13

/** Minimum initialization vector (nonce) size in bytes */
#define MIN_CCM_IV_SIZE 7

/** Error code returned when CCM tag verification fails during decryption */
#define OPENSSL_TAG_MISMATCH_ERROR -6

/** @} */ // end of CCM_Constants

/**
 * Initialize a CCM cipher context for encryption or decryption.
 *
 * This function sets up the CCM cipher with the specified key, IV (nonce),
 * and tag length. The tag length must be even and between 4-16 bytes.
 * The IV length must be between 7-13 bytes.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID from previous cipher creation
 * @param encrypt Non-zero for encryption, zero for decryption
 * @param key Byte array containing the encryption key
 * @param iv Byte array containing the initialization vector (nonce)
 * @param tagLen Length of the authentication tag (4-16 bytes, must be even)
 *
 * @throws OpenSSLException if initialization fails or parameters are invalid
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1init(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen);

/**
 * Update CCM cipher with input data and optional AAD.
 *
 * This function processes input data through the CCM cipher. Additional
 * Authenticated Data (AAD) can be provided for authentication without
 * encryption. This function can be called multiple times for streaming
 * operations.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param encrypt Non-zero for encryption, zero for decryption
 * @param input Input data byte array
 * @param inputOffset Offset in input array
 * @param inputLen Length of input data to process
 * @param output Output buffer for processed data
 * @param outputOffset Offset in output array
 * @param aad Additional Authenticated Data (can be NULL)
 * @param aadLen Length of AAD
 * @return Number of bytes written to output, or -1 on error
 *
 * @throws OpenSSLException if update operation fails
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_update
 * Signature: (JJII[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1update(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen);

/**
 * Finalize CCM encryption and generate authentication tag.
 *
 * This function completes the CCM encryption operation, processes any
 * remaining input data, and generates the authentication tag. The tag
 * is appended to the ciphertext in the output buffer.
 *
 * For CCM mode, the plaintext length must be set before processing AAD,
 * which is handled internally by this function.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Final input data (can be NULL for zero-length plaintext)
 * @param inputOffset Offset in input array
 * @param inputLen Length of final input data
 * @param output Output buffer (must be large enough for ciphertext + tag)
 * @param outputOffset Offset in output array
 * @param aad Additional Authenticated Data (can be NULL)
 * @param aadLen Length of AAD
 * @param tagLen Length of authentication tag to generate
 * @return Total bytes written (ciphertext + tag), or -1 on error
 *
 * @throws OpenSSLException if finalization fails
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_encryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen);

/**
 * Finalize CCM decryption and verify authentication tag.
 *
 * This function completes the CCM decryption operation, processes the
 * ciphertext, and verifies the authentication tag. The input must include
 * both the ciphertext and the appended authentication tag.
 *
 * Tag verification is performed automatically. If verification fails,
 * OPENSSL_TAG_MISMATCH_ERROR is returned and an exception is thrown.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Input data containing ciphertext + tag
 * @param inputOffset Offset in input array
 * @param inputLen Total length of input (ciphertext + tag)
 * @param output Output buffer for decrypted plaintext
 * @param outputOffset Offset in output array
 * @param aad Additional Authenticated Data (must match encryption AAD)
 * @param aadLen Length of AAD
 * @param tagLen Length of authentication tag
 * @return Number of plaintext bytes written, or OPENSSL_TAG_MISMATCH_ERROR
 *         if tag verification fails, or -1 on other errors
 *
 * @throws OpenSSLException if decryption or tag verification fails
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_decryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong contextId, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen);

#endif 