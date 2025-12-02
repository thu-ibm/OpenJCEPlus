/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

public class OpenSSLException extends Exception {
    private static final long serialVersionUID = 1L;

    // These must match the values in OpenSSLExceptionCodes.h
    public static final int OPENSSL_FIPS_MODE_INVALID = 0x00000001;
    public static final int OPENSSL_LIBRARY_LOAD_FAILED = 0x00000002;
    public static final int OPENSSL_PROVIDER_LOAD_FAILED = 0x00000003;
    public static final int OPENSSL_CIPHER_INIT_FAILED = 0x00000009;
    public static final int OPENSSL_CIPHER_UPDATE_FAILED = 0x0000000A;
    public static final int OPENSSL_CIPHER_FINAL_FAILED = 0x0000000B;
    public static final int OPENSSL_CIPHER_TAG_MISMATCH = 0x0000000E;
    public static final int OPENSSL_UNSPECIFIED = 0x80000000;

    private int errorCode;

    public OpenSSLException(String message) {
        super(message);
        this.errorCode = 0;
    }

    public OpenSSLException(String message, int errorCode) {
        super(message + " (Error code: " + errorCode + " - " + getErrorCodeString(errorCode) + ")");
        this.errorCode = errorCode;
    }

    public OpenSSLException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = 0;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public static String getErrorCodeString(int code) {
        switch (code) {
            case OPENSSL_FIPS_MODE_INVALID:
                return "OPENSSL_FIPS_MODE_INVALID";
            case OPENSSL_LIBRARY_LOAD_FAILED:
                return "OPENSSL_LIBRARY_LOAD_FAILED";
            case OPENSSL_PROVIDER_LOAD_FAILED:
                return "OPENSSL_PROVIDER_LOAD_FAILED";
            case OPENSSL_CIPHER_INIT_FAILED:
                return "OPENSSL_CIPHER_INIT_FAILED";
            case OPENSSL_CIPHER_UPDATE_FAILED:
                return "OPENSSL_CIPHER_UPDATE_FAILED";
            case OPENSSL_CIPHER_FINAL_FAILED:
                return "OPENSSL_CIPHER_FINAL_FAILED";
            case OPENSSL_CIPHER_TAG_MISMATCH:
                return "OPENSSL_CIPHER_TAG_MISMATCH";
            case OPENSSL_UNSPECIFIED:
                return "OPENSSL_UNSPECIFIED";
            default:
                return "UNKNOWN_ERROR_CODE_" + code;
        }
    }

    public String getErrorCodeString() {
        return getErrorCodeString(errorCode);
    }

    @Override
    public String toString() {
        return super.toString() + " [Error code: " + errorCode + " - " + getErrorCodeString() + "]";
    }
}
