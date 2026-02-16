/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_EXCEPTION_CODES_H
#define _OPENSSL_EXCEPTION_CODES_H

// These constants must match those defined in com.ibm.crypto.plus.provider.openssl.OpenSSLException

#define OPENSSL_FIPS_MODE_INVALID 0x00000001
#define OPENSSL_LIBRARY_LOAD_FAILED 0x00000002
#define OPENSSL_PROVIDER_LOAD_FAILED 0x00000003
#define OPENSSL_DIGEST_INIT_FAILED 0x00000004
#define OPENSSL_DIGEST_UPDATE_FAILED 0x00000005
#define OPENSSL_DIGEST_FINAL_FAILED 0x00000006
#define OPENSSL_RAND_SEED_FAILED 0x00000007
#define OPENSSL_RAND_BYTES_FAILED 0x00000008
#define OPENSSL_CIPHER_INIT_FAILED 0x00000009
#define OPENSSL_CIPHER_UPDATE_FAILED 0x0000000A
#define OPENSSL_CIPHER_FINAL_FAILED 0x0000000B
#define OPENSSL_CIPHER_TAG_MISMATCH 0x0000000E
#define OPENSSL_UNSPECIFIED 0x80000000

#endif
