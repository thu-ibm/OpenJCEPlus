/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLNativeInterface.h
 * @brief Main JNI interface for OpenSSL context management.
 *
 * This header defines the primary context management functions for the
 * OpenSSL JNI bridge. These functions handle initialization, cleanup,
 * and querying of OpenSSL contexts.
 *
 * The context management provides:
 * - Initialization of OpenSSL library and providers
 * - FIPS mode configuration
 * - Context lifecycle management
 * - Version and configuration queries
 */

#ifndef _OPENSSL_NATIVE_INTERFACE_H
#define _OPENSSL_NATIVE_INTERFACE_H

#include <jni.h>

/**
 * Initialize OpenSSL library and create a context.
 * This must be called before any other OpenSSL operations.
 *
 * @param env JNI environment
 * @param cls Java class
 * @return Context ID for subsequent operations, or -1 on error
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_initializeOpenSSL(
    JNIEnv* env, jclass cls);

/**
 * Clean up OpenSSL context and free resources.
 * Should be called when the context is no longer needed.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Context ID to clean up
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_cleanupOpenSSL(
    JNIEnv* env, jclass cls, jlong contextId);

/**
 * Get a configuration value from the OpenSSL context.
 * Values include FIPS mode status, OpenSSL version, and installation path.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Context ID
 * @param valueId Value identifier (see OpenSSLContext.h constants)
 * @return String value, or NULL on error
 */
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CTX_1getValue(
    JNIEnv* env, jclass cls, jlong contextId, jint valueId);

#endif
