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

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLLogging.h"
#include "OpenSSLSymmetricCipher.h"

int debug = 0;

static OpenSSLContext* nonFipsContext = NULL;
static OpenSSLContext* fipsContext    = NULL;

static OpenSSLContext* createContext(JNIEnv* env, int isFIPS);
static void            freeInternalContext(OpenSSLContext* context);
static int             isFIPSSupported(void);

static int isFIPSSupported(void) {
    OSSL_LIB_CTX* testCtx = OSSL_LIB_CTX_new();
    if (testCtx == NULL) {
        return 0;
    }

    OSSL_PROVIDER* fips      = OSSL_PROVIDER_load(testCtx, "fips");
    int            supported = (fips != NULL);

    if (fips != NULL) {
        OSSL_PROVIDER_unload(fips);
    }
    OSSL_LIB_CTX_free(testCtx);

    return supported;
}

static OpenSSLContext* createContext(JNIEnv* env, int isFIPS) {
    static const char* functionName = "OpenSSLUtils.createContext";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (isFIPS && !isFIPSSupported()) {
        throwOpenSSLException(
            env, OPENSSL_FIPS_MODE_INVALID,
            "FIPS mode requested but FIPS provider is not available");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    OpenSSLContext* context = (OpenSSLContext*)malloc(sizeof(OpenSSLContext));
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to allocate memory for OpenSSL context");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    memset(context, 0, sizeof(OpenSSLContext));
    context->id     = isFIPS ? 2 : 1;
    context->isFIPS = isFIPS;

    context->libctx = OSSL_LIB_CTX_new();
    if (context->libctx == NULL) {
        free(context);
        throwOpenSSLException(env, OPENSSL_LIBRARY_LOAD_FAILED,
                              "Failed to create OpenSSL library context");
        logOpenSSLError("OSSL_LIB_CTX_new");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    if (isFIPS) {
        context->fips = OSSL_PROVIDER_load(context->libctx, "fips");
        if (context->fips == NULL) {
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load FIPS provider");
            logOpenSSLError("OSSL_PROVIDER_load(fips)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return NULL;
        }

        if (EVP_default_properties_enable_fips(context->libctx, 1) != 1) {
            OSSL_PROVIDER_unload(context->fips);
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            throwOpenSSLException(env, OPENSSL_FIPS_MODE_INVALID,
                                  "Failed to enable FIPS mode");
            logOpenSSLError("EVP_default_properties_enable_fips");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return NULL;
        }

        context->base = OSSL_PROVIDER_load(context->libctx, "base");
        if (context->base == NULL) {
            OSSL_PROVIDER_unload(context->fips);
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load base provider");
            logOpenSSLError("OSSL_PROVIDER_load(base)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return NULL;
        }

#ifdef DEBUG_OPENSSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_OPENSSL FIPS provider and base provider loaded, FIPS mode enabled");
        }
#endif
    } else {
        context->defaultProv = OSSL_PROVIDER_load(context->libctx, "default");
        if (context->defaultProv == NULL) {
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            throwOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load default provider");
            logOpenSSLError("OSSL_PROVIDER_load(default)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return NULL;
        }

#ifdef DEBUG_OPENSSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_OPENSSL Default provider loaded");
        }
#endif
    }

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage("DETAIL_OPENSSL OpenSSL context created successfully (ID: %ld, FIPS: %d)",
                     context->id, context->isFIPS);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }
    return context;
}

OpenSSLContext* getOrCreateContext(JNIEnv* env, int isFIPS) {
    OpenSSLContext* context = isFIPS ? fipsContext : nonFipsContext;

    if (context == NULL) {
        context = createContext(env, isFIPS);
        if (context != NULL) {
            if (isFIPS) {
                fipsContext = context;
            } else {
                nonFipsContext = context;
            }
        }
    }

    return context;
}

static void freeInternalContext(OpenSSLContext* context) {
    if (context != NULL) {
        if (context->fips != NULL) {
            OSSL_PROVIDER_unload(context->fips);
        }
        if (context->defaultProv != NULL) {
            OSSL_PROVIDER_unload(context->defaultProv);
        }
        if (context->base != NULL) {
            OSSL_PROVIDER_unload(context->base);
        }
        if (context->libctx != NULL) {
            OSSL_LIB_CTX_free(context->libctx);
        }
        free(context);
    }
}

#ifndef _MSC_VER
__attribute__((destructor))
#endif
static void cleanupContexts(void) {
    if (nonFipsContext != NULL) {
        freeInternalContext(nonFipsContext);
        nonFipsContext = NULL;
    }

    if (fipsContext != NULL) {
        freeInternalContext(fipsContext);
        fipsContext = NULL;
    }

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage("DETAIL_OPENSSL OpenSSL contexts cleaned up");
    }
#endif
}
int validateCipherContext(JNIEnv*         env,
                         jlong           fipsFlag,
                         jlong           cipherId,
                         const char*     functionName,
                         CipherContext** outCipherCtx) {
    int             isFIPS  = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);

    if (context == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    if (outCipherCtx != NULL) {
        *outCipherCtx = cipherCtx;
    }

    return 1;
}


static jclass    openSSLExceptionClass               = NULL;
static jmethodID openSSLExceptionConstructor         = NULL;
static jmethodID openSSLExceptionConstructorWithCode = NULL;


void throwOpenSSLException(JNIEnv* env, int code, const char* msg) {
    jstring jMsg;

    if (openSSLExceptionClass == NULL) {
        openSSLExceptionClass = (*env)->FindClass(
            env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (openSSLExceptionClass == NULL) {
            return; // Exception already thrown
        }
        openSSLExceptionClass =
            (*env)->NewGlobalRef(env, openSSLExceptionClass);
        openSSLExceptionConstructor = (*env)->GetMethodID(
            env, openSSLExceptionClass, "<init>", "(Ljava/lang/String;)V");
        openSSLExceptionConstructorWithCode = (*env)->GetMethodID(
            env, openSSLExceptionClass, "<init>", "(Ljava/lang/String;I)V");
    }

    jMsg = (*env)->NewStringUTF(env, msg);
    if (jMsg == NULL) {
        return; // OutOfMemoryError already thrown
    }

    jobject exception;
    if (code != 0) {
        exception =
            (*env)->NewObject(env, openSSLExceptionClass,
                              openSSLExceptionConstructorWithCode, jMsg, code);
    } else {
        exception = (*env)->NewObject(env, openSSLExceptionClass,
                                      openSSLExceptionConstructor, jMsg);
    }

    if (exception != NULL) {
        (*env)->Throw(env, exception);
    }
}

char* getOpenSSLErrorString(void) {
    char* buf = malloc(256);
    if (buf == NULL) {
        return NULL;
    }

    unsigned long err = ERR_get_error();
    if (err == 0) {
        strcpy(buf, "No OpenSSL error");
    } else {
        ERR_error_string_n(err, buf, 256);
    }

    return buf;
}

void cleanupByteArrays(JNIEnv*    env,
                       jbyteArray keyArray,
                       jbyte*     keyBytes,
                       jbyteArray ivArray,
                       jbyte*     ivBytes) {
    if (keyBytes != NULL && keyArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, keyArray, keyBytes, JNI_ABORT);
    }
    if (ivBytes != NULL && ivArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, ivArray, ivBytes, JNI_ABORT);
    }
}

void cleanupIOArrays(JNIEnv*    env,
                     jbyteArray inputArray,
                     jbyte*     inputBytes,
                     jbyteArray outputArray,
                     jbyte*     outputBytes,
                     jboolean   commitOutput) {
    if (inputBytes != NULL && inputArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArray, inputBytes, JNI_ABORT);
    }
    if (outputBytes != NULL && outputArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, outputArray, outputBytes,
                                         commitOutput ? 0 : JNI_ABORT);
    }
}


void logOpenSSLError(const char* prefix) {
    if (debug) {
        char* errStr = getOpenSSLErrorString();
        if (errStr != NULL) {
            fprintf(stderr, "%s: %s\n", prefix, errStr);
            free(errStr);
        }
    }
}

void logHexData(const unsigned char* data, int length, const char* prefix) {
    if (debug && data != NULL && length > 0) {
        fprintf(stderr, "%s: ", prefix);
        for (int i = 0; i < length; i++) {
            fprintf(stderr, "%02x", data[i]);
            if ((i + 1) % 16 == 0 && i < length - 1) {
                fprintf(stderr, "\n%s: ", prefix);
            } else if (i < length - 1) {
                fprintf(stderr, " ");
            }
        }
        fprintf(stderr, "\n");
    }
}

jclass getOpenSSLExceptionClass(JNIEnv* env) {
    if (openSSLExceptionClass == NULL) {
        openSSLExceptionClass = (*env)->FindClass(
            env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (openSSLExceptionClass == NULL) {
            return NULL;
        }
        openSSLExceptionClass =
            (*env)->NewGlobalRef(env, openSSLExceptionClass);
    }
    return openSSLExceptionClass;
}


int gslogFunctionEntry(const char* functionName) {
    return gslogMessage("Entering %s", functionName);
}

int gslogError(const char* formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    static char printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsprintf(printBuffer, formatString, formatArgs);

    fprintf(stderr, "[ERROR] %s\n", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

int gslogMessage(const char* formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    static char printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsprintf(printBuffer, formatString, formatArgs);

    fprintf(stderr, "[DEBUG] %s\n", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

int gslogMessagePrefix(const char* formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    static char printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsprintf(printBuffer, formatString, formatArgs);

    fprintf(stderr, "[DEBUG] %s", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

int gslogMessageHex(char bytes[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix) {
    int index;
    int charsPrinted = 0;

    for (index = 1; index <= length; index++) {
        charsPrinted +=
            fprintf(stderr, "%2.2X", (unsigned char)bytes[offset + index - 1]);
        if ((newlineAfter > 0) && ((index % newlineAfter) == 0) &&
            (index < length)) {
            charsPrinted += fprintf(stderr, "\n");
            if (newlinePrefix != NULL) {
                charsPrinted += fprintf(stderr, "%s", newlinePrefix);
            }
        } else if ((spaceAfter > 0) && ((index % spaceAfter) == 0)) {
            charsPrinted += fprintf(stderr, " ");
        }
    }
    charsPrinted += fprintf(stderr, "\n");
    fflush(stderr);
    return charsPrinted;
}

int gslogFunctionExit(const char* functionName) {
    return gslogMessage("Exiting %s", functionName);
}
