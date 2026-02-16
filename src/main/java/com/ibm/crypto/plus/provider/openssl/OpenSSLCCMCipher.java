/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

/**
 * OpenSSL CCM (Counter with CBC-MAC) cipher implementation.
 *
 * This class provides a Java wrapper around OpenSSL's CCM mode implementation.
 * CCM is an authenticated encryption mode that combines CTR mode encryption
 * with CBC-MAC authentication.
 *
 * Key features:
 * - Authenticated encryption with associated data (AEAD)
 * - Configurable tag length (4-16 bytes)
 * - Configurable IV length (7-13 bytes for AES)
 * - Single-pass operation (no separate update calls)
 *
 * Thread Safety:
 * This class is NOT thread-safe. Each thread should use its own instance.
 *
 * Context Management:
 * - Uses centralized OpenSSL context management from OpenSSLUtils
 * - Contexts are lazily initialized on first use
 * - FIPS mode is automatically detected and validated
 * - Contexts are automatically cleaned up
 */
public final class OpenSSLCCMCipher implements AutoCloseable {

    private final String algorithm;
    private long cipherId = 0;
    private boolean isFIPS = false;

    /**
     * Creates a new OpenSSL CCM cipher instance.
     *
     * @param isFIPS Whether FIPS mode is enabled
     * @param algorithm The cipher algorithm (e.g., "AES-128-CCM", "AES-192-CCM", "AES-256-CCM")
     * @throws OpenSSLException if the cipher cannot be created
     */
    private OpenSSLCCMCipher(boolean isFIPS, String algorithm) throws OpenSSLException {
        this.algorithm = algorithm;
        this.isFIPS = isFIPS;

        // Create the cipher - context will be lazily initialized in native code
        synchronized (this) {
            this.cipherId = OpenSSLNativeInterface.CIPHER_create(
                    isFIPS ? 1L : 0L,  // Pass FIPS flag instead of context ID
                    algorithm
            );

            if (this.cipherId == 0 || this.cipherId == -1) {
                throw new OpenSSLException("Failed to create CCM cipher: " + algorithm);
            }
        }
    }

    /**
     * Gets an instance of the OpenSSL CCM cipher for AES-CCM.
     *
     * @param opensslContext The OpenSSL context
     * @param numKeyBytes The number of key bytes (16, 24, or 32)
     * @return A new OpenSSLCCMCipher instance
     * @throws OpenSSLException if the cipher cannot be created
     */
    public static OpenSSLCCMCipher getInstance(OpenSSLContext opensslContext, int numKeyBytes)
            throws OpenSSLException {
        if (opensslContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (numKeyBytes != 16 && numKeyBytes != 24 && numKeyBytes != 32) {
            throw new IllegalArgumentException("Invalid key size: " + numKeyBytes);
        }

        String cipherName = "AES-" + (numKeyBytes * 8) + "-CCM";
        return new OpenSSLCCMCipher(opensslContext.isFIPS(), cipherName);
    }

    /**
     * Initializes the CCM cipher for encryption or decryption.
     *
     * @param encrypt true for encryption, false for decryption
     * @param key The encryption key
     * @param iv The initialization vector (nonce)
     * @param tagLen The authentication tag length in bytes (4-16)
     * @throws OpenSSLException if initialization fails
     */
    public synchronized void init(boolean encrypt, byte[] key, byte[] iv, int tagLen)
            throws OpenSSLException {
        if (cipherId == 0 || cipherId == -1) {
            throw new OpenSSLException("Cipher not initialized");
        }

        if (key == null || key.length == 0) {
            throw new OpenSSLException("Key cannot be null or empty");
        }

        if (iv == null || iv.length < 7 || iv.length > 13) {
            throw new OpenSSLException("IV must be between 7 and 13 bytes for CCM");
        }

        if (tagLen < 4 || tagLen > 16 || tagLen % 2 != 0) {
            throw new OpenSSLException("Tag length must be even and between 4 and 16 bytes");
        }

        OpenSSLNativeInterface.CCM_init(
                isFIPS ? 1L : 0L,  // Pass FIPS flag
                cipherId,
                encrypt ? 1 : 0,
                key,
                iv,
                tagLen
        );
    }

    /**
     * Processes data with optional additional authenticated data (AAD).
     *
     * Note: CCM mode typically requires all data to be provided at once.
     * This method is provided for compatibility but may have limitations.
     *
     * @param encrypt true for encryption, false for decryption
     * @param input The input data
     * @param inputOffset Offset in the input array
     * @param inputLen Length of input data
     * @param output The output buffer
     * @param outputOffset Offset in the output array
     * @param aad Additional authenticated data (can be null)
     * @return The number of bytes written to output
     * @throws OpenSSLException if the operation fails
     */
    public synchronized int update(boolean encrypt, byte[] input, int inputOffset, int inputLen,
                                   byte[] output, int outputOffset, byte[] aad)
            throws OpenSSLException {
        if (cipherId == 0 || cipherId == -1) {
            throw new OpenSSLException("Cipher not initialized");
        }

        int aadLen = (aad != null) ? aad.length : 0;

        return OpenSSLNativeInterface.CCM_update(
                isFIPS ? 1L : 0L,  // Pass FIPS flag
                cipherId,
                encrypt ? 1 : 0,
                input,
                inputOffset,
                inputLen,
                output,
                outputOffset,
                aad,
                aadLen
        );
    }

    /**
     * Completes the CCM encryption or decryption operation.
     *
     * For encryption: Processes the final input data and appends the authentication tag.
     * For decryption: Processes the final input data and verifies the authentication tag.
     *
     * @param encrypt true for encryption, false for decryption
     * @param input The final input data (including tag for decryption)
     * @param inputOffset Offset in the input array
     * @param inputLen Length of input data
     * @param output The output buffer
     * @param outputOffset Offset in the output array
     * @param aad Additional authenticated data (can be null)
     * @param tagLen The authentication tag length in bytes
     * @return The number of bytes written to output (including tag for encryption)
     * @throws OpenSSLException if the operation fails or tag verification fails
     */
    public synchronized int doFinal(boolean encrypt, byte[] input, int inputOffset, int inputLen,
                                    byte[] output, int outputOffset, byte[] aad, int tagLen)
            throws OpenSSLException {
        if (cipherId == 0 || cipherId == -1) {
            throw new OpenSSLException("Cipher not initialized");
        }

        int aadLen = (aad != null) ? aad.length : 0;
        long fipsFlag = isFIPS ? 1L : 0L;
        int result;

        if (encrypt) {
            result = OpenSSLNativeInterface.CCM_encryptFinal(
                    fipsFlag,
                    cipherId,
                    input,
                    inputOffset,
                    inputLen,
                    output,
                    outputOffset,
                    aad,
                    aadLen,
                    tagLen
            );
        } else {
            result = OpenSSLNativeInterface.CCM_decryptFinal(
                    fipsFlag,
                    cipherId,
                    input,
                    inputOffset,
                    inputLen,
                    output,
                    outputOffset,
                    aad,
                    aadLen,
                    tagLen
            );
        }

        if (result == -6) {
            throw new OpenSSLException("CCM tag verification failed",
                    OpenSSLException.OPENSSL_CIPHER_TAG_MISMATCH);
        }

        return result;
    }

    /**
     * Gets the cipher ID.
     *
     * @return The native cipher ID
     */
    public long getCipherId() {
        return cipherId;
    }

    /**
     * Gets the algorithm name.
     *
     * @return The cipher algorithm name
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Checks if FIPS mode is enabled.
     *
     * @return true if FIPS mode is enabled
     */
    public boolean isFIPS() {
        return isFIPS;
    }

    /**
     * Closes this cipher and releases native resources.
     *
     * Note: The OpenSSL context is managed internally and will be
     * automatically cleaned up when the library is unloaded.
     */
    @Override
    public synchronized void close() {
        if (cipherId != 0 && cipherId != -1) {
            try {
                OpenSSLNativeInterface.CIPHER_delete(
                        isFIPS ? 1L : 0L,  // Pass FIPS flag
                        cipherId
                );
            } catch (Exception e) {
                // Ignore exceptions during cleanup
            } finally {
                cipherId = 0;
            }
        }
    }

    /**
     * Ensures native resources are released when this object is garbage collected.
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
}

