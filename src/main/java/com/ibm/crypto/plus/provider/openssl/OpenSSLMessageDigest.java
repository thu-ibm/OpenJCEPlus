/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.Arrays;

/**
 * OpenSSL-based message digest implementation.
 * This class provides direct access to OpenSSL 3.0 digest functions.
 */
public final class OpenSSLMessageDigest extends MessageDigestSpi implements Cloneable {

    private boolean isFIPS;  // FIPS mode flag
    private long opensslDigestId;
    private String algorithm;
    private int digestLength;
    private boolean isInitialized = false;

    private static final String badIdMsg = "Digest Identifier is not valid";

    /**
     * Get an instance of MD5 digest
     */
    public static OpenSSLMessageDigest getInstanceMD5(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "MD5");
    }

    /**
     * Get an instance of SHA-1 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA1(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA1");
    }

    /**
     * Get an instance of SHA-224 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA224(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA224");
    }

    /**
     * Get an instance of SHA-256 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA256(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA256");
    }

    /**
     * Get an instance of SHA-384 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA384(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA384");
    }

    /**
     * Get an instance of SHA-512 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA512(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA512");
    }

    /**
     * Get an instance of SHA-512/224 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA512_224(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA512-224");
    }

    /**
     * Get an instance of SHA-512/256 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA512_256(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA512-256");
    }

    /**
     * Get an instance of SHA3-224 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA3_224(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-224");
    }

    /**
     * Get an instance of SHA3-256 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA3_256(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-256");
    }

    /**
     * Get an instance of SHA3-384 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA3_384(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-384");
    }

    /**
     * Get an instance of SHA3-512 digest
     */
    public static OpenSSLMessageDigest getInstanceSHA3_512(OpenSSLContext opensslContext)
            throws OpenSSLException {
        return getInstance(opensslContext.isFIPS(), "SHA3-512");
    }

    /**
     * Private factory method to create digest instances
     */
    private static OpenSSLMessageDigest getInstance(boolean isFIPS, String algorithm)
            throws OpenSSLException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("algorithm is null/empty");
        }
        return new OpenSSLMessageDigest(isFIPS, algorithm);
    }

    /**
     * Private constructor
     */
    private OpenSSLMessageDigest(boolean isFIPS, String algorithm) throws OpenSSLException {
        this.isFIPS = isFIPS;
        this.algorithm = algorithm;

        // Pass FIPS flag (0=non-FIPS, 1=FIPS)
        int fipsFlag = isFIPS ? 1 : 0;
        this.opensslDigestId = OpenSSLNativeInterface.DIGEST_create(fipsFlag, algorithm);

        if (this.opensslDigestId == 0L) {
            throw new OpenSSLException("Failed to create digest context for " + algorithm);
        }

        // Get digest length
        this.digestLength = OpenSSLNativeInterface.DIGEST_size(fipsFlag, opensslDigestId);
        this.isInitialized = true;
    }

    /**
     * Returns the digest length in bytes
     */
    @Override
    public int engineGetDigestLength() {
        return digestLength;
    }

    /**
     * Updates the digest using the specified byte
     */
    @Override
    protected synchronized void engineUpdate(byte input) {
        byte[] temp = new byte[1];
        temp[0] = input;
        engineUpdate(temp, 0, 1);
    }

    /**
     * Updates the digest using the specified array of bytes
     */
    @Override
    public synchronized void engineUpdate(byte[] input, int offset, int len) {
        if (!isInitialized) {
            throw new IllegalStateException("Digest not initialized");
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

        if (opensslDigestId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            int result = OpenSSLNativeInterface.DIGEST_update(fipsFlag, opensslDigestId,
                    input, offset, len);
            if (result < 0) {
                throw new IllegalStateException("Digest update failed with code: " + result);
            }
        } catch (OpenSSLException e) {
            throw new IllegalStateException("Digest update failed", e);
        }
    }

    /**
     * Completes the hash computation and returns the digest
     */
    @Override
    public synchronized byte[] engineDigest() {
        if (!isInitialized) {
            throw new IllegalStateException("Digest not initialized");
        }

        if (opensslDigestId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            byte[] digest = OpenSSLNativeInterface.DIGEST_digest(fipsFlag, opensslDigestId);

            if (digest == null || digest.length != digestLength) {
                throw new IllegalStateException("Digest operation returned invalid result");
            }

            return digest;
        } catch (OpenSSLException e) {
            throw new IllegalStateException("Digest operation failed", e);
        }
    }

    /**
     * Completes the hash computation and stores the digest in the provided buffer
     */
    @Override
    protected synchronized int engineDigest(byte[] buf, int offset, int len)
            throws DigestException {
        if (!isInitialized) {
            throw new IllegalStateException("Digest not initialized");
        }

        if (buf == null) {
            throw new IllegalArgumentException("output buffer is null");
        }

        if (offset < 0 || len < 0 || (offset + len) > buf.length) {
            throw new DigestException("Invalid offset or length");
        }

        if (len < digestLength) {
            throw new DigestException("Output buffer too small. Need " + digestLength +
                    " bytes, but only " + len + " available");
        }

        byte[] digest = engineDigest();
        System.arraycopy(digest, 0, buf, offset, digestLength);
        Arrays.fill(digest, (byte) 0x00);

        return digestLength;
    }

    /**
     * Resets the digest for further use
     */
    @Override
    public synchronized void engineReset() {
        if (!isInitialized) {
            return;
        }

        if (opensslDigestId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            int fipsFlag = isFIPS ? 1 : 0;
            OpenSSLNativeInterface.DIGEST_reset(fipsFlag, opensslDigestId);
        } catch (OpenSSLException e) {
            throw new IllegalStateException("Digest reset failed", e);
        }
    }

    /**
     * Returns a clone of this digest object
     */
    @Override
    public synchronized Object clone() throws CloneNotSupportedException {
        if (!isInitialized) {
            throw new IllegalStateException("Digest not initialized");
        }

        if (opensslDigestId == 0L) {
            throw new IllegalStateException(badIdMsg);
        }

        try {
            OpenSSLMessageDigest cloned = (OpenSSLMessageDigest) super.clone();

            // Create a new native context by copying the current one
            int fipsFlag = isFIPS ? 1 : 0;
            cloned.opensslDigestId = OpenSSLNativeInterface.DIGEST_copy(fipsFlag, opensslDigestId);

            if (cloned.opensslDigestId == 0L) {
                throw new CloneNotSupportedException("Failed to copy digest context");
            }

            return cloned;
        } catch (OpenSSLException e) {
            throw new CloneNotSupportedException("Failed to clone digest: " + e.getMessage());
        }
    }

    /**
     * Cleanup native resources
     */
    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            if (opensslDigestId != 0L) {
                int fipsFlag = isFIPS ? 1 : 0;
                OpenSSLNativeInterface.DIGEST_delete(fipsFlag, opensslDigestId);
                opensslDigestId = 0L;
            }
        } finally {
            super.finalize();
        }
    }

    /**
     * Get the algorithm name
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Check if this digest is in FIPS mode
     */
    public boolean isFIPS() {
        return isFIPS;
    }
}


