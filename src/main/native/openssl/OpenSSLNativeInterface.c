/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
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

// Next context ID
static jlong nextContextId = 1;

// Context map 
#define MAX_CONTEXTS 100
static OpenSSLContext *contextMap[MAX_CONTEXTS] = {NULL};

// Forward declarations
static void initializeDebug(void);
static void freeContext(OpenSSLContext *context);
static jlong addContext(OpenSSLContext *context);
static void removeContext(jlong contextId);

// Context management functions
OpenSSLContext *getContext(jlong contextId) {
    for (int i = 0; i < MAX_CONTEXTS; i++) {
        if (contextMap[i] != NULL && contextMap[i]->id == contextId) {
            return contextMap[i];
        }
    }
    return NULL;
}

static void freeContext(OpenSSLContext *context) {
    if (context != NULL) {
        if (context->fips != NULL) {
            OSSL_PROVIDER_unload(context->fips);
        }
        if (context->defaultProv != NULL) {
            OSSL_PROVIDER_unload(context->defaultProv);
        }
        if (context->libctx != NULL) {
            OSSL_LIB_CTX_free(context->libctx);
        }
        free(context);
    }
}

static jlong addContext(OpenSSLContext *context) {
    for (int i = 0; i < MAX_CONTEXTS; i++) {
        if (contextMap[i] == NULL) {
            contextMap[i] = context;
            return context->id;
        }
    }
    return -1; // No space available
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

// Initialize debug flag
static void initializeDebug(void) {
    static int initialized = 0;
    
    if (!initialized) {
        char *debugEnv = getenv("OPENSSL_DEBUG");
        if (debugEnv != NULL && (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
            debug = 1;
        }
        initialized = 1;
    }
}

// This runs BEFORE any JNI methods are called
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    // Initialize debug flag immediately when library loads
    char *debugEnv = getenv("OPENSSL_DEBUG");
    if (debugEnv != NULL && (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
        debug = 1;
        fprintf(stderr, "[OpenSSL JNI] Debug logging ENABLED (OPENSSL_DEBUG=%s)\n", debugEnv);
        fflush(stderr);
    } else {
        fprintf(stderr, "[OpenSSL JNI] Debug logging DISABLED (set OPENSSL_DEBUG=1 to enable)\n");
        fflush(stderr);
    }
    
    return JNI_VERSION_1_8;
}

// JNI method implementations

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    initializeOpenSSL
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_initializeOpenSSL
  (JNIEnv *env, jclass cls, jboolean isFIPS) {
    logFunctionEntry("initializeOpenSSL");
    
    // Initialize debug flag
    initializeDebug();
    
    // Create a new OpenSSL context
    OpenSSLContext *context = (OpenSSLContext *)malloc(sizeof(OpenSSLContext));
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to allocate memory for OpenSSL context");
        logFunctionExit("initializeOpenSSL");
        return -1;
    }
    
    // Initialize the context
    memset(context, 0, sizeof(OpenSSLContext));
    context->id = nextContextId++;
    context->isFIPS = isFIPS;
    
    // Create a new OpenSSL library context
    context->libctx = OSSL_LIB_CTX_new();
    if (context->libctx == NULL) {
        free(context);
        throwOpenSSLException(env, OPENSSL_LIBRARY_LOAD_FAILED, "Failed to create OpenSSL library context");
        logOpenSSLError("OSSL_LIB_CTX_new");
        logFunctionExit("initializeOpenSSL");
        return -1;
    }
    
    // Load providers
    if (isFIPS) {
        // Load FIPS provider
        context->fips = OSSL_PROVIDER_load(context->libctx, "fips");
        if (context->fips == NULL) {
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED, "Failed to load FIPS provider");
            logOpenSSLError("OSSL_PROVIDER_load(fips)");
            logFunctionExit("initializeOpenSSL");
            return -1;
        }
        
        // Set FIPS mode
        EVP_default_properties_enable_fips(context->libctx, 1);
    }
    
    // Load defaultProv provider
    context->defaultProv = OSSL_PROVIDER_load(context->libctx, "default");
    if (context->defaultProv == NULL) {
        if (context->fips != NULL) {
            OSSL_PROVIDER_unload(context->fips);
        }
        OSSL_LIB_CTX_free(context->libctx);
        free(context);
        throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED, "Failed to load default provider");
        logOpenSSLError("OSSL_PROVIDER_load(defaultProv)");
        logFunctionExit("initializeOpenSSL");
        return -1;
    }
    
    // Add the context to the map
    jlong contextId = addContext(context);
    if (contextId == -1) {
        freeContext(context);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to add OpenSSL context to map");
        logFunctionExit("initializeOpenSSL");
        return -1;
    }
    
    logMessage("OpenSSL initialized with context ID %ld, FIPS mode: %d", contextId, isFIPS);
    logFunctionExit("initializeOpenSSL");
    return contextId;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    cleanupOpenSSL
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_cleanupOpenSSL
  (JNIEnv *env, jclass cls, jlong contextId) {
    logFunctionEntry("cleanupOpenSSL");
    
    // Remove the context from the map
    removeContext(contextId);
    
    logMessage("OpenSSL context %ld cleaned up", contextId);
    logFunctionExit("cleanupOpenSSL");
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CTX_getValue
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CTX_1getValue
  (JNIEnv *env, jclass cls, jlong contextId, jint valueId) {
    logFunctionEntry("CTX_getValue");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CTX_getValue");
        return NULL;
    }
    
    jstring result = NULL;
    
    switch (valueId) {
        case VALUE_FIPS_APPROVED_MODE:
            result = (*env)->NewStringUTF(env, context->isFIPS ? "true" : "false");
            break;
            
        case VALUE_OPENSSL_VERSION:
            result = (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));
            break;
            
        case VALUE_OPENSSL_INSTALL_PATH:
            result = (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_DIR));
            break;
            
        default:
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid value ID");
            break;
    }
    
    logFunctionExit("CTX_getValue");
    return result;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    getByteBufferPointer
 * Signature: (Ljava/nio/ByteBuffer;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_getByteBufferPointer
  (JNIEnv *env, jclass cls, jobject buffer) {
    logFunctionEntry("getByteBufferPointer");
    
    void *ptr = (*env)->GetDirectBufferAddress(env, buffer);
    
    logFunctionExit("getByteBufferPointer");
    return (jlong)ptr;
}

