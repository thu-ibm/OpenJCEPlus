/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_CONTEXT_H
#define _OPENSSL_CONTEXT_H

#include <jni.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// NOTE: These constants must match those defined in
//       com.ibm.crypto.plus.provider.openssl.OpenSSLContext
//
#define VALUE_FIPS_APPROVED_MODE 0
#define VALUE_OPENSSL_VERSION 1
#define VALUE_OPENSSL_INSTALL_PATH 2

// OpenSSL context structure
typedef struct {
    jlong id;                // Context ID
    int isFIPS;              // Whether FIPS mode is enabled
    OSSL_LIB_CTX *libctx;    // OpenSSL library context
    OSSL_PROVIDER *fips;     // FIPS provider
    OSSL_PROVIDER *defaultProv;  // Default provider 
} OpenSSLContext;

#endif 

