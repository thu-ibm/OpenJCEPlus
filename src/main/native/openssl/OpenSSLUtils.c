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

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"

// Debug flag
int debug = 0;

// JNI class and method references
static jclass openSSLExceptionClass = NULL;
static jmethodID openSSLExceptionConstructor = NULL;
static jmethodID openSSLExceptionConstructorWithCode = NULL;

/**
 * Throws an OpenSSLException with the specified message and error code.
 *
 * @param env the JNI environment
 * @param code the error code
 * @param msg the error message
 */
void throwOpenSSLException(JNIEnv *env, int code, const char *msg) {
    jstring jMsg;
    
    if (openSSLExceptionClass == NULL) {
        openSSLExceptionClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (openSSLExceptionClass == NULL) {
            return; // Exception already thrown
        }
        openSSLExceptionClass = (*env)->NewGlobalRef(env, openSSLExceptionClass);
        openSSLExceptionConstructor = (*env)->GetMethodID(env, openSSLExceptionClass, "<init>", "(Ljava/lang/String;)V");
        openSSLExceptionConstructorWithCode = (*env)->GetMethodID(env, openSSLExceptionClass, "<init>", "(Ljava/lang/String;I)V");
    }
    
    jMsg = (*env)->NewStringUTF(env, msg);
    if (jMsg == NULL) {
        return; // OutOfMemoryError already thrown
    }
    
    jobject exception;
    if (code != 0) {
        exception = (*env)->NewObject(env, openSSLExceptionClass, openSSLExceptionConstructorWithCode, jMsg, code);
    } else {
        exception = (*env)->NewObject(env, openSSLExceptionClass, openSSLExceptionConstructor, jMsg);
    }
    
    if (exception != NULL) {
        (*env)->Throw(env, exception);
    }
}

/**
 * Gets the OpenSSL error string.
 *
 * @return the error string (must be freed by the caller)
 */
char *getOpenSSLErrorString(void) {
    char *buf = malloc(256);
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

/**
 * Logs an OpenSSL error.
 *
 * @param prefix the prefix to add to the error message
 */
void logOpenSSLError(const char *prefix) {
    if (debug) {
        char *errStr = getOpenSSLErrorString();
        if (errStr != NULL) {
            fprintf(stderr, "%s: %s\n", prefix, errStr);
            free(errStr);
        }
    }
}

/**
 * Logs a message.
 *
 * @param format the format string
 * @param ... the arguments
 */
void logMessage(const char *format, ...) {
    if (debug) {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        fprintf(stderr, "\n");
    }
}

/**
 * Logs a function entry.
 *
 * @param functionName the function name
 */
void logFunctionEntry(const char *functionName) {
    if (debug) {
        fprintf(stderr, "Utilizing OpenSSL: Entering %s\n", functionName);
    }
}

/**
 * Logs a function exit.
 *
 * @param functionName the function name
 */
void logFunctionExit(const char *functionName) {
    if (debug) {
        fprintf(stderr, "Exiting %s\n", functionName);
    }
}

/**
 * Logs hex data.
 *
 * @param data the data
 * @param length the length of the data
 * @param prefix the prefix to add to the log message
 */
void logHexData(const unsigned char *data, int length, const char *prefix) {
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

/**
 * Gets the OpenSSLException class.
 *
 * @param env the JNI environment
 * @return the OpenSSLException class
 */
jclass getOpenSSLExceptionClass(JNIEnv *env) {
    if (openSSLExceptionClass == NULL) {
        openSSLExceptionClass = (*env)->FindClass(env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (openSSLExceptionClass == NULL) {
            return NULL; // Exception already thrown
        }
        openSSLExceptionClass = (*env)->NewGlobalRef(env, openSSLExceptionClass);
    }
    return openSSLExceptionClass;
}

