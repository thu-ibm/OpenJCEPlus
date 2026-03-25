/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLNativeInterface.c
 * @brief Main implementation of OpenSSL JNI context management.
 *
 * This file implements the core context management functionality for the
 * OpenSSL JNI bridge, including:
 * - Library initialization and cleanup
 * - FIPS and non-FIPS context creation
 * - Provider loading (FIPS, base, default)
 * - Context lifecycle management
 * - Debug logging initialization
 * - JNI_OnLoad for library initialization
 *
 * The implementation maintains a context map to track active OpenSSL
 * contexts and ensures proper resource cleanup on library unload.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "OpenSSLNativeInterface.h"
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

// Next context ID
static jlong nextContextId = 1;

#define MAX_CONTEXTS 100
static OpenSSLContext* contextMap[MAX_CONTEXTS] = {NULL};

static void  initializeDebug(void);
static void  freeContext(OpenSSLContext* context);
static jlong addContext(OpenSSLContext* context);
static void  removeContext(jlong contextId);

// Context management functions
OpenSSLContext* getContext(jlong contextId) {
    for (int i = 0; i < MAX_CONTEXTS; i++) {
        if (contextMap[i] != NULL && contextMap[i]->id == contextId) {
            return contextMap[i];
        }
    }
    return NULL;
}

static void freeContext(OpenSSLContext* context) {
    if (context != NULL) {
        if (context->fips != NULL) {
            OSSL_PROVIDER_unload(context->fips);
        }
        if (context->base != NULL) {
            OSSL_PROVIDER_unload(context->base);
        }
        // libctx is NULL (using default context), so no need to free
        free(context);
    }
}

static jlong addContext(OpenSSLContext* context) {
    for (int i = 0; i < MAX_CONTEXTS; i++) {
        if (contextMap[i] == NULL) {
            contextMap[i] = context;
            return context->id;
        }
    }
    return -1;
}

static void removeContext(jlong contextId) {
    for (int i = 0; i < MAX_CONTEXTS; i++) {
        if (contextMap[i] != NULL && contextMap[i]->id == contextId) {
            freeContext(contextMap[i]);
            contextMap[i] = NULL;
            return;
        }
    }
}

static void initializeDebug(void) {
    static int initialized = 0;

    if (!initialized) {
        char* debugEnv = getenv("OPENSSL_DEBUG");
        if (debugEnv != NULL &&
            (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
            debug = 1;
        }
        initialized = 1;
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    char* debugEnv = getenv("OPENSSL_DEBUG");
    if (debugEnv != NULL &&
        (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
        debug = 1;
        fprintf(stderr,
                "[OpenSSL JNI] Debug logging ENABLED (OPENSSL_DEBUG=%s)\n",
                debugEnv);
        fflush(stderr);
    } else {
        fprintf(stderr,
                "[OpenSSL JNI] Debug logging DISABLED (set OPENSSL_DEBUG=1 to "
                "enable)\n");
        fflush(stderr);
    }

    return JNI_VERSION_1_8;
}

// JNI method implementations

//============================================================================
// initializeOpenSSL - Initialize OpenSSL context with FIPS or non-FIPS mode
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_initializeOpenSSL(
    JNIEnv* env, jclass cls, jboolean isFIPS) {
    static const char* functionName =
        "OpenSSLNativeInterface.initializeOpenSSL";

    // Initialize debug flag
    initializeDebug();

    // Create a new OpenSSL context (already zeroed by mallocSafe)
    OpenSSLContext* context = (OpenSSLContext*)mallocSafe(
        env, sizeof(OpenSSLContext), "Failed to allocate memory for OpenSSL context");
    if (context == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

    // Initialize the context
    context->id     = nextContextId++;
    context->isFIPS = isFIPS;

    // Use NULL (default context) to pick up openssl.cnf configuration
    // Creating a new context bypasses the global configuration
    context->libctx = NULL;

    // Load providers
    if (isFIPS) {
        context->fips = OSSL_PROVIDER_load(context->libctx, "fips");
        if (context->fips == NULL) {
            free(context);
            throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load FIPS provider");
            logOpenSSLError("OSSL_PROVIDER_load(fips)");
            logFunctionExit(functionName);
            return -1;
        }

        EVP_default_properties_enable_fips(context->libctx, 1);
    }

    context->base = OSSL_PROVIDER_load(context->libctx, "base");
    if (context->base == NULL) {
        if (context->fips != NULL) {
            OSSL_PROVIDER_unload(context->fips);
        }
        free(context);
        throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                              "Failed to load base provider");
        logOpenSSLError("OSSL_PROVIDER_load(base)");
        logFunctionExit(functionName);
        return -1;
    }

    // Add the context to the map
    jlong contextId = addContext(context);
    if (contextId == -1) {
        freeContext(context);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to add OpenSSL context to map");
        logFunctionExit(functionName);
        return -1;
    }

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_OPENSSL OpenSSL initialized with context ID %ld, FIPS "
            "mode: %d",
            contextId, isFIPS);
    }
#endif

    logFunctionExit(functionName);
    return contextId;
}

//============================================================================
// cleanupOpenSSL - Cleanup OpenSSL context and free resources
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_cleanupOpenSSL(
    JNIEnv* env, jclass cls, jlong contextId) {
    static const char* functionName = "OpenSSLNativeInterface.cleanupOpenSSL";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    removeContext(contextId);

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage("DETAIL_OPENSSL OpenSSL context %ld cleaned up",
                     contextId);
    }
#endif

    logFunctionExit(functionName);
}

//============================================================================
// CTX_getValue - Get context value (FIPS mode, version, install path)
//============================================================================
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CTX_1getValue(
    JNIEnv* env, jclass cls, jlong contextId, jint valueId) {
    static const char* functionName = "OpenSSLNativeInterface.CTX_getValue";

    // Get the context
    OpenSSLContext* context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid OpenSSL context ID");
        logFunctionExit(functionName);
        return NULL;
    }

    jstring result = NULL;

    switch (valueId) {
        case VALUE_FIPS_APPROVED_MODE:
            result =
                (*env)->NewStringUTF(env, context->isFIPS ? "true" : "false");
            break;

        case VALUE_OPENSSL_VERSION:
            result =
                (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));
            break;

        case VALUE_OPENSSL_INSTALL_PATH:
            result = (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_DIR));
            break;

        default:
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid value ID");
            break;
    }

    logFunctionExit(functionName);
    return result;
}

//============================================================================
// getByteBufferPointer - Get native pointer from direct ByteBuffer
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_getByteBufferPointer(
    JNIEnv* env, jclass cls, jobject buffer) {
    static const char* functionName =
        "OpenSSLNativeInterface.getByteBufferPointer";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    void* ptr = (*env)->GetDirectBufferAddress(env, buffer);

    logFunctionExit(functionName);
    return (jlong)ptr;
}
