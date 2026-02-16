/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.util.Arrays;

/**
 * AES-GCM cipher implementation using OpenSSL.
 * This class provides AEAD (Authenticated Encryption with Associated Data) operations.
 *
 * <p>Note: This class implements AutoCloseable for explicit resource management.
 * While finalize() is used as a safety net, it's recommended to explicitly call
 * close() or use try-with-resources for deterministic cleanup.
 *
 * <p>GCM Mode Features:
 * <ul>
 *   <li>Authenticated encryption with associated data (AEAD)</li>
 *   <li>Configurable authentication tag length (12-16 bytes recommended)</li>
 *   <li>Support for additional authenticated data (AAD)</li>
 *   <li>Single-shot and multi-part operations</li>
 * </ul>
 */
public final class OpenSSLGCMCipher implements AutoCloseable {

    private boolean isFIPS;  // 0=non-FIPS, 1=FIPS
    private long opensslCipherId;
    private boolean isInitialized = false;
    private boolean encrypting = true;
    private int tagLen = 16; // Default GCM tag length in bytes
    private int bufferedCount = 0;
    private int keyLength = 0;
    private int ivLength = 0;
    private boolean needsReinit = false;
    private byte[] reinitKey = null;
    private byte[] reinitIV = null;
    private byte[] aad = null; // Additional Authenticated Data
    private boolean aadProcessed = false; // Track if AAD has been processed

    // AES-GCM constants
    private static final int AES_GCM_MIN_KEY_SIZE = 16;
    private static final int AES_GCM_MIN_IV_SIZE = 1;
    private static final int AES_GCM_DEFAULT_TAG_LEN = 16;
    private static final int AES_GCM_MIN_TAG_LEN = 4;
    private static final int AES_GCM_MAX_TAG_LEN = 16;
    private static final byte[] emptyAAD = new byte[0];

    private static final String badIdMsg = "Cipher Identifier is not valid";

    /**
     * Gets an instance of OpenSSLGCMCipher for AES-GCM.
     *
     * @param opensslContext the OpenSSL context
     * @param numKeyBytes the number of key bytes (16, 24, or 32)
     * @return the OpenSSLGCMCipher instance
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public static OpenSSLGCMCipher getInstance(OpenSSLContext opensslContext, int numKeyBytes)
            throws OpenSSLException {
        if (opensslContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (numKeyBytes != 16 && numKeyBytes != 24 && numKeyBytes != 32) {
            throw new IllegalArgumentException("Invalid key size: " + numKeyBytes);
        }

        String cipherName = "AES-" + (numKeyBytes * 8) + "-GCM";
        return new OpenSSLGCMCipher(opensslContext.isFIPS(), cipherName);
    }

    /**
     * Constructs a new OpenSSLGCMCipher.
     *
     * @param isFIPS 0=non-FIPS, 1=FIPS
     * @param cipherName the cipher name (e.g., "AES-128-GCM")
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    private OpenSSLGCMCipher(boolean isFIPS, String cipherName)
            throws OpenSSLException {
        this.isFIPS = isFIPS;
        // Pass FIPS flag as contextId (0=non-FIPS, 1=FIPS)
        long fipsFlag = isFIPS ? 1L : 0L;
        this.opensslCipherId = OpenSSLNativeInterface.CIPHER_create(fipsFlag, cipherName);
    }

    /**
     * Sets the authentication tag length.
     *
     * @param tagLen the tag length in bytes (12-16 recommended)
     * @throws IllegalArgumentException if tag length is invalid
     */
    public synchronized void setTagLen(int tagLen) {
        System.out.println("taglen: " + tagLen);
        if (tagLen < AES_GCM_MIN_TAG_LEN || tagLen > AES_GCM_MAX_TAG_LEN) {
            throw new IllegalArgumentException(
                    "Tag length must be between " + AES_GCM_MIN_TAG_LEN +
                            " and " + AES_GCM_MAX_TAG_LEN + " bytes");
        }
        this.tagLen = tagLen;
    }

    /**
     * Gets the authentication tag length.
     *
     * @return the tag length in bytes
     */
    public synchronized int getTagLen() {
        return this.tagLen;
    }

    /**
     * Sets the Additional Authenticated Data (AAD).
     * Must be called after init and before any update/doFinal operations.
     *
     * @param aad the additional authenticated data
     */
    public synchronized void setAAD(byte[] aad) {
        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
        this.aad = (aad != null) ? aad.clone() : emptyAAD.clone();
    }

    /**
     * Initializes the cipher for encryption.
     *
     * @param key the key
     * @param iv the initialization vector
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public synchronized void initCipherEncrypt(byte[] key, byte[] iv) throws OpenSSLException {
        initCipher(true, key, iv);
    }

    /**
     * Initializes the cipher for decryption.
     *
     * @param key the key
     * @param iv the initialization vector
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public synchronized void initCipherDecrypt(byte[] key, byte[] iv) throws OpenSSLException {
        initCipher(false, key, iv);
    }

    /**
     * Initializes the cipher.
     *
     * @param isEncrypt whether to initialize for encryption
     * @param key the key
     * @param iv the initialization vector
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    private void initCipher(boolean isEncrypt, byte[] key, byte[] iv) throws OpenSSLException {
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }
        if (key.length < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }
        if ((iv == null) || (iv.length < AES_GCM_MIN_IV_SIZE)) {
            throw new IllegalArgumentException("IV is null or wrong size");
        }

        if (opensslCipherId == 0L) {
            throw new OpenSSLException(badIdMsg);
        }

        // Initialize the cipher with GCM mode
        long fipsFlag = isFIPS ? 1L : 0L;
        OpenSSLNativeInterface.GCM_init(fipsFlag, opensslCipherId,
                isEncrypt ? 1 : 0, key, iv, tagLen);

        this.encrypting = isEncrypt;
        this.bufferedCount = 0;
        this.needsReinit = false;
        this.aad = null; // Reset AAD
        this.aadProcessed = false; // Reset AAD processed flag

        if (key != reinitKey) {
            if (reinitKey != null) {
                Arrays.fill(reinitKey, (byte) 0x00);
            }
            this.reinitKey = key.clone();
        }
        if (iv != reinitIV) {
            this.reinitIV = (iv == null) ? null : iv.clone();
        }
        this.isInitialized = true;
    }

    /**
     * Gets the output size for the given input length.
     *
     * @param inputLen the input length
     * @return the output size
     */
    public int getOutputSize(int inputLen) {
        return getOutputSize(inputLen, true);
    }

    /**
     * Gets the output size for the given input length.
     * For GCM:
     * - Encryption: outputSize = inputLen + tagLen
     * - Decryption: outputSize = inputLen - tagLen
     *
     * @param inputLen the input length
     * @param isFinal whether this is the final block
     * @return the output size
     */
    public synchronized int getOutputSize(int inputLen, boolean isFinal) {
        if (inputLen < 0) {
            return 0;
        }

        int totalLen = this.bufferedCount + inputLen;

        if (!isFinal) {
            // For update operations, return the input length
            return totalLen;
        }

        // For doFinal operations
        if (encrypting) {
            // Encryption: add space for tag
            return totalLen + tagLen;
        } else {
            // Decryption: subtract tag
            int result = totalLen - tagLen;
            return (result < 0) ? 0 : result;
        }
    }

    /**
     * Gets the key length.
     *
     * @return the key length
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public synchronized int getKeyLength() throws OpenSSLException {
        if (keyLength == 0) {
            if (opensslCipherId == 0L) {
                throw new OpenSSLException(badIdMsg);
            }
            long fipsFlag = isFIPS ? 1L : 0L;
            keyLength = OpenSSLNativeInterface.CIPHER_getKeyLength(fipsFlag, opensslCipherId);
        }
        return keyLength;
    }

    /**
     * Gets the IV length.
     *
     * @return the IV length
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public synchronized int getIVLength() throws OpenSSLException {
        if (ivLength == 0) {
            if (opensslCipherId == 0L) {
                throw new OpenSSLException(badIdMsg);
            }
            long fipsFlag = isFIPS ? 1L : 0L;
            ivLength = OpenSSLNativeInterface.CIPHER_getIVLength(fipsFlag, opensslCipherId);
        }
        return ivLength;
    }

    /**
     * Updates the cipher with the given input.
     * For GCM, this processes plaintext/ciphertext data.
     *
     * @param input the input data
     * @param inputOffset the offset into the input data
     * @param inputLen the length of the input data
     * @param output the output buffer
     * @param outputOffset the offset into the output buffer
     * @return the number of bytes written to the output buffer
     * @throws IllegalStateException if the cipher is not initialized
     * @throws ShortBufferException if the output buffer is too small
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public synchronized int update(byte[] input, int inputOffset, int inputLen, byte[] output,
                                   int outputOffset)
            throws IllegalStateException, ShortBufferException, OpenSSLException {

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (inputLen == 0) {
            return 0;
        }

        if (input == null || inputLen < 0 || inputOffset < 0
                || (inputOffset + inputLen) > input.length) {
            throw new IllegalArgumentException("Input range is invalid");
        }

        if (output == null || outputOffset < 0 || (outputOffset > output.length)) {
            throw new IllegalArgumentException("Output range is invalid");
        }

        int len = getOutputSize(inputLen, false);
        if ((output.length - outputOffset) < len) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        // Handle overlapping input/output buffers
        byte[] copyOfInput = null;
        if (input == output) {
            if ((inputOffset == outputOffset)
                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset + inputLen)))
                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
                copyOfInput = new byte[inputLen];
                System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
                input = copyOfInput;
                inputOffset = 0;
            }
        }

        try {
            if (opensslCipherId == 0L) {
                throw new OpenSSLException(badIdMsg);
            }

            // Pass AAD on first update call if it's set and not yet processed
            byte[] aadData = null;
            int aadLen = 0;
            if (this.aad != null && !this.aadProcessed) {
                aadData = this.aad;
                aadLen = this.aad.length;
                this.aadProcessed = true; // Mark as processed
            }

            long fipsFlag = isFIPS ? 1L : 0L;
            int outLen = OpenSSLNativeInterface.GCM_update(fipsFlag, opensslCipherId,
                    encrypting ? 1 : 0, input, inputOffset, inputLen, output, outputOffset,
                    aadData, aadLen);

            if (outLen < 0) {
                throw new OpenSSLException("GCM update failed with error code: " + outLen);
            }

            if (outLen > (output.length - outputOffset)) {
                throw new ShortBufferException(
                        "Output buffer must be (at least) " + outLen + " bytes long");
            }

            this.bufferedCount += inputLen - outLen;
            return outLen;
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }
    }

    /**
     * Finalizes the cipher operation.
     * For GCM encryption, this appends the authentication tag.
     * For GCM decryption, this verifies the authentication tag.
     *
     * @param input the input data
     * @param inputOffset the offset into the input data
     * @param inputLen the length of the input data
     * @param output the output buffer
     * @param outputOffset the offset into the output buffer
     * @return the number of bytes written to the output buffer
     * @throws IllegalStateException if the cipher is not initialized
     * @throws ShortBufferException if the output buffer is too small
     * @throws IllegalBlockSizeException if the input data is invalid
     * @throws BadPaddingException if the padding is invalid
     * @throws AEADBadTagException if tag verification fails during decryption
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    public synchronized int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
                                    int outputOffset) throws IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException, OpenSSLException {

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (inputLen != 0) {
            if (input == null || inputLen < 0 || inputOffset < 0
                    || (inputOffset + inputLen) > input.length) {
                throw new IllegalArgumentException("Input range is invalid");
            }
        }

        if ((output == null) || (outputOffset < 0) || (outputOffset > output.length)) {
            throw new IllegalArgumentException("Output range is invalid");
        }

        int len = getOutputSize(inputLen);
        if ((output.length - outputOffset) < len) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        // Handle overlapping input/output buffers
        byte[] copyOfInput = null;
        if (input == output) {
            if ((inputOffset == outputOffset)
                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset + inputLen)))
                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
                copyOfInput = new byte[inputLen];
                System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
                input = copyOfInput;
                inputOffset = 0;
            }
        }

        try {
            if (opensslCipherId == 0L) {
                throw new OpenSSLException(badIdMsg);
            }

            // Pass AAD if it hasn't been processed yet (single-shot operation)
            byte[] aadData = null;
            int aadLen = 0;
            if (this.aad != null && !this.aadProcessed) {
                aadData = this.aad;
                aadLen = this.aad.length;
                this.aadProcessed = true; // Mark as processed
            } else {
                aadData = emptyAAD;
                aadLen = 0;
            }

            long fipsFlag = isFIPS ? 1L : 0L;
            int outLen;
            if (encrypting) {
                outLen = OpenSSLNativeInterface.GCM_encryptFinal(fipsFlag, opensslCipherId,
                        input, inputOffset, inputLen, output, outputOffset,
                        aadData, aadLen, tagLen);
            } else {
                outLen = OpenSSLNativeInterface.GCM_decryptFinal(fipsFlag, opensslCipherId,
                        input, inputOffset, inputLen, output, outputOffset,
                        aadData, aadLen, tagLen);
            }

            if (outLen < 0) {
                if (outLen == -6) { // Tag mismatch error code
                    throw new AEADBadTagException("Tag mismatch!");
                }
                throw new OpenSSLException("GCM final failed with error code: " + outLen);
            }

            if (outLen > (output.length - outputOffset)) {
                throw new ShortBufferException(
                        "Output buffer must be (at least) " + outLen + " bytes long");
            }

            // Reset state for reuse
            this.bufferedCount = 0;
            this.needsReinit = true;
            this.aad = null;
            this.aadProcessed = false;

            return outLen;
        } catch (OpenSSLException e) {
            // Check if this is a tag mismatch error
            if (e.getErrorCode() == OpenSSLException.OPENSSL_CIPHER_TAG_MISMATCH) {
                throw new AEADBadTagException("Tag mismatch!");
            }
            throw e;
        } catch (AEADBadTagException e) {
            throw e;
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }
    }

    /**
     * Explicitly closes and releases native resources.
     * This method should be called when the cipher is no longer needed.
     * It is safe to call this method multiple times.
     *
     * @throws OpenSSLException if an error occurs during cleanup
     */
    @Override
    public synchronized void close() throws OpenSSLException {
        if (opensslCipherId != 0) {
            long fipsFlag = isFIPS ? 1L : 0L;
            OpenSSLNativeInterface.CIPHER_delete(fipsFlag, opensslCipherId);
            opensslCipherId = 0;
        }
        if (reinitKey != null) {
            Arrays.fill(reinitKey, (byte) 0x00);
            reinitKey = null;
        }
        if (aad != null) {
            Arrays.fill(aad, (byte) 0x00);
            aad = null;
        }
    }

    /**
     * Finalizes the cipher as a safety net for resource cleanup.
     * Note: finalize() is deprecated but kept for compatibility with OCK pattern.
     * Prefer using close() or try-with-resources for explicit cleanup.
     *
     * @throws Throwable if an error occurs
     */
    @SuppressWarnings("removal")
    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            close();
        } catch (OpenSSLException e) {
            // Ignore exceptions during finalization
        } finally {
            super.finalize();
        }
    }
}
