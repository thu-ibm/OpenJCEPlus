/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLUtils.h
 * @brief Core utility functions for OpenSSL JNI integration.
 *
 * This header provides fundamental utilities for OpenSSL operations including:
 * - Context management (FIPS and non-FIPS modes)
 * - Exception handling and error reporting
 * - Debug logging infrastructure
 * - OpenSSL error string extraction
 *
 * These utilities form the foundation for all OpenSSL native operations
 * and ensure consistent error handling and logging across the codebase.
 */

#ifndef _OPENSSL_UTILS_H
#define _OPENSSL_UTILS_H

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"

/** Return code for successful operations */
#define OPENSSL_SUCCESS 0

/** Return code for failed operations */
#define OPENSSL_FAILURE -1

/**
 * Macro to safely free memory and set pointer to NULL.
 * Prevents double-free errors and use-after-free bugs.
 */
#define FREE_AND_NULL(ptr) \
    if ((ptr) != NULL) {   \
        free((ptr));       \
        (ptr) = NULL;      \
    }

/** Global debug flag - set to non-zero to enable debug logging */
extern int debug;

//============================================================================
// Logging Functions
//============================================================================

/** Log function entry (if debug enabled) */
int gslogFunctionEntry(const char* functionName);

/** Log error message */
int gslogError(const char* formatString, ...);

/** Log informational message */
int gslogMessage(const char* formatString, ...);

/** Log message with prefix */
int gslogMessagePrefix(const char* formatString, ...);

/** Log binary data as hexadecimal */
int gslogMessageHex(char byte[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix);

/** Log function exit (if debug enabled) */
int gslogFunctionExit(const char* functionName);

//============================================================================
// Exception and Error Handling
//============================================================================

/**
 * Throw an OpenSSLException to Java with specified error code and message.
 * @param env JNI environment
 * @param code Error code from OpenSSLExceptionCodes.h
 * @param msg Error message
 */
void throwOpenSSLException(JNIEnv* env, int code, const char* msg);

/**
 * Get the current OpenSSL error as a string.
 * @return Dynamically allocated error string (caller must free)
 */
char* getOpenSSLErrorString(void);

/**
 * Log the current OpenSSL error with a prefix.
 * @param prefix Prefix string for the log message
 */
void logOpenSSLError(const char* prefix);

/**
 * Log binary data as hexadecimal with a prefix.
 * @param data Binary data to log
 * @param length Length of data
 * @param prefix Prefix string for the log message
 */
void logHexData(const unsigned char* data, int length, const char* prefix);

/**
 * Get the OpenSSLException class reference.
 * @param env JNI environment
 * @return Java class reference for OpenSSLException
 */
jclass getOpenSSLExceptionClass(JNIEnv* env);

//============================================================================
// Context Management
//============================================================================

/**
 * Get or create an OpenSSL context for the specified mode.
 * Contexts are cached and reused. Thread-safe.
 *
 * @param env JNI environment
 * @param isFIPS Non-zero for FIPS mode, zero for non-FIPS mode
 * @return OpenSSL context pointer, or NULL on error (exception thrown)
 */
OpenSSLContext* getOrCreateContext(JNIEnv* env, int isFIPS);

#endif
