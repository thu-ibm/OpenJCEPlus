/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * OpenSSL-based HMAC implementation.
 * This class provides direct access to OpenSSL 3.0 HMAC functions.
 */
public final class OpenSSLHMAC extends MacSpi implements Cloneable {

    private boolean isFIPS;  // FIPS mode flag
    private long opensslHmacId;
    private String algorithm;
    private int macLength;
    private boolean isInitialized = false;
    private byte[] keyBytes = null;

    private static final String badIdMsg = "HMAC Identifier is not valid";

    /**
     * Get an instance of HmacMD5
     */
    public static OpenSSLHMAC getInstanceHmacMD5(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "MD5");
    }

    /**
     * Get an instance of HmacSHA1
     */
    public static OpenSSLHMAC getInstanceHmacSHA1(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA1");
    }

    /**
     * Get an instance of HmacSHA224
     */
    public static OpenSSLHMAC getInstanceHmacSHA224(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA224");
    }

    /**
     * Get an instance of HmacSHA256
     */
    public static OpenSSLHMAC getInstanceHmacSHA256(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA256");
    }

    /**
     * Get an instance of HmacSHA384
     */
    public static OpenSSLHMAC getInstanceHmacSHA384(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA384");
    }

    /**
     * Get an instance of HmacSHA512
     */
    public static OpenSSLHMAC getInstanceHmacSHA512(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA512");
    }

    /**
     * Get an instance of HmacSHA3-224
     */
    public static OpenSSLHMAC getInstanceHmacSHA3_224(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-224");
    }

    /**
     * Get an instance of HmacSHA3-256
     */
    public static OpenSSLHMAC getInstanceHmacSHA3_256(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-256");
    }

    /**
     * Get an instance of HmacSHA3-384
     */
    public static OpenSSLHMAC getInstanceHmacSHA3_384(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-384");
    }

    /**
     * Get an instance of HmacSHA3-512
     */
    public static OpenSSLHMAC getInstanceHmacSHA3_512(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-512");
    }

    /**
     * Private factory method to create HMAC instances
     */
    private static OpenSSLHMAC getInstance(boolean isFIPS, String algorithm)
            throws OpenSSLException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("algorithm is null/empty");
        }
        return new OpenSSLHMAC(isFIPS, algorithm);
    }

    /**
     * Private constructor
     */
    private OpenSSLHMAC(boolean isFIPS, String algorithm) throws OpenSSLException {
        this.isFIPS = isFIPS;
        this.algorithm = algorithm;

        // Pass FIPS flag (0=non-FIPS, 1=FIPS)
        int fipsFlag = isFIPS ? 1 : 0;
        this.opensslHmacId = OpenSSLNativeInterface.HMAC_create(fipsFlag, algorithm);

        if (this.opensslHmacId == 0L) {
            throw new OpenSSLException("Failed to create HMAC context for " + algorithm);
        }

        // Get MAC length
        this.macLength = OpenSSLNativeInterface.HMAC_size(fipsFlag, opensslHmacId);
    }

    /**
     * Returns the length of the MAC in bytes
     */
    @Override
    public int engineGetMacLength() {
        return macLength;
    }

    /**
     * Initializes the HMAC with the given key
     */
    @Override
    public synchronized void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "HMAC does not use algorithm parameters");
        }

        if (key == null) {
            throw new InvalidKeyException("Key is null");
        }

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey");
        }

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        if (opensslHmacId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            int result = OpenSSLNativeInterface.HMAC_init(fipsFlag, opensslHmacId,
                    keyBytes, keyBytes.length);

            if (result < 0) {
                throw new InvalidKeyException("HMAC initialization failed with code: " + result);
            }

            // Store key for potential reset operations
            this.keyBytes = keyBytes.clone();
            this.isInitialized = true;

        } catch (OpenSSLException e) {
            throw new InvalidKeyException("HMAC initialization failed", e);
        } finally {
            // Clear sensitive key data
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    /**
     * Processes the given byte
     */
    @Override
    public synchronized void engineUpdate(byte input) {
        byte[] temp = new byte[1];
        temp[0] = input;
        engineUpdate(temp, 0, 1);
    }

    /**
     * Processes the given array of bytes
     */
    @Override
    public synchronized void engineUpdate(byte[] input, int offset, int len) {
        if (!isInitialized) {
            throw new IllegalStateException("HMAC not initialized");
        }

        if (input == null) {
            throw new IllegalArgumentException("input is null");
        }

        if (len == 0) {
            return;
        }

        if (offset < 0 || len < 0 || (offset + len) > input.length) {
            throw new IllegalArgumentException("Invalid offset or length");
        }

        if (opensslHmacId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            int result = OpenSSLNativeInterface.HMAC_update(fipsFlag, opensslHmacId,
                    input, offset, len);

            if (result < 0) {
                throw new IllegalStateException("HMAC update failed with code: " + result);
            }
        } catch (OpenSSLException e) {
            throw new IllegalStateException("HMAC update failed", e);
        }
    }

    /**
     * Completes the HMAC computation and returns the MAC
     */
    @Override
    public synchronized byte[] engineDoFinal() {
        if (!isInitialized) {
            throw new IllegalStateException("HMAC not initialized");
        }

        if (opensslHmacId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            byte[] mac = new byte[macLength];
            int result = OpenSSLNativeInterface.HMAC_doFinal(fipsFlag, opensslHmacId, mac);

            if (result != 1) {
                throw new IllegalStateException("HMAC operation failed with result: " + result);
            }

            return mac;
        } catch (OpenSSLException e) {
            throw new IllegalStateException("HMAC operation failed", e);
        }
    }

    /**
     * Resets the HMAC for further use, maintaining the secret key
     */
    @Override
    public synchronized void engineReset() {
        if (!isInitialized) {
            return; // Nothing to reset
        }

        if (opensslHmacId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            OpenSSLNativeInterface.HMAC_reset(fipsFlag, opensslHmacId);

            // Re-initialize with the stored key
            if (keyBytes != null) {
                int result = OpenSSLNativeInterface.HMAC_init(fipsFlag, opensslHmacId,
                        keyBytes, keyBytes.length);

                if (result < 0) {
                    throw new IllegalStateException("HMAC re-initialization failed with code: " + result);
                }
            }
        } catch (OpenSSLException e) {
            throw new IllegalStateException("HMAC reset failed", e);
        }
    }

    /**
     * Returns a clone of this HMAC object
     */
    @Override
    public synchronized Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("OpenSSL HMAC cloning not yet supported");
    }

    /**
     * Finalizer to ensure native resources are freed
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            if (opensslHmacId != 0L) {
                int fipsFlag = isFIPS ? 1 : 0;
                try {
                    OpenSSLNativeInterface.HMAC_delete(fipsFlag, opensslHmacId);
                } catch (OpenSSLException e) {
                    // Ignore exceptions during finalization
                }
                opensslHmacId = 0L;
            }

            // Clear sensitive key data
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
                keyBytes = null;
            }
        } finally {
            super.finalize();
        }
    }

    /**
     * Explicitly releases native resources
     */
    public synchronized void dispose() {
        if (opensslHmacId != 0L) {
            int fipsFlag = isFIPS ? 1 : 0;
            try {
                OpenSSLNativeInterface.HMAC_delete(fipsFlag, opensslHmacId);
            } catch (OpenSSLException e) {
                // Log but don't throw during cleanup
                System.err.println("Warning: Failed to delete HMAC context: " + e.getMessage());
            }
            opensslHmacId = 0L;
        }

        // Clear sensitive key data
        if (keyBytes != null) {
            Arrays.fill(keyBytes, (byte) 0);
            keyBytes = null;
        }

        isInitialized = false;
    }

    /**
     * Gets the algorithm name
     */
    public String getAlgorithm() {
        return "Hmac" + algorithm;
    }

    /**
     * Checks if FIPS mode is enabled
     */
    public boolean isFIPS() {
        return isFIPS;
    }
}

