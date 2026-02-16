/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_KEYWRAP_H
#define _OPENSSL_KEYWRAP_H

#include <jni.h>

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    KEYWRAP_wrap
 * Signature: (J[B[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_KEYWRAP_1wrap(
    JNIEnv* env, jclass thisObj, jlong fipsFlag, jbyteArray plaintext,
    jbyteArray kek, jboolean padding);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    KEYWRAP_unwrap
 * Signature: (J[B[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_KEYWRAP_1unwrap(
    JNIEnv* env, jclass thisObj, jlong fipsFlag, jbyteArray ciphertext,
    jbyteArray kek, jboolean padding);

#endif
