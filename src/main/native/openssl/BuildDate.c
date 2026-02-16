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
#include <assert.h>

#include "com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface.h"
#include "OpenSSLLogging.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    getLibraryBuildDate
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_getLibraryBuildDate(
    JNIEnv* env, jclass thisObj) {
    static const char* functionName =
        "OpenSSLNativeInterface.getLibraryBuildDate";
    const char* buildDateString = NULL;
    jstring     retValue        = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif

#if defined(BUILD_DATE)
    buildDateString = BUILD_DATE;
#elif defined(__DATE__) && defined(__TIME__)
    buildDateString = __DATE__ " " __TIME__;
#elif defined(__DATE__)
    buildDateString = __DATE__;
#else
    buildDateString = "<UNKNOWN>";
#endif

#ifdef __MVS__
#pragma convert(pop)
#endif

    if (buildDateString != NULL) {
        retValue = (*env)->NewStringUTF(env, buildDateString);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retValue;
}
