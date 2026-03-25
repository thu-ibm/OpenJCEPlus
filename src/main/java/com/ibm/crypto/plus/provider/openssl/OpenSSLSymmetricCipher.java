/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.util.Arrays;

public final class OpenSSLSymmetricCipher {

    private boolean isFIPS;  // FIPS mode flag 
    private long opensslCipherId;
    private boolean isInitialized = false;
    private boolean encrypting = true;
    private Padding padding = null;
    private int bufferedCount = 0;
    private int blockSize = 0;
    private int keyLength = 0;
    private int ivLength = 0;
    private boolean needsReinit = false;
    private byte[] reinitKey = null;
    private byte[] reinitIV = null;

    private static final String badIdMsg = "Cipher Identifier is not valid";


    public static OpenSSLSymmetricCipher getInstanceChaCha20(OpenSSLContext opensslContext, Padding padding)
            throws OpenSSLException {
        String algName = "chacha20";
        return getInstance(opensslContext.isFIPS(), algName, padding);
    }

    public static OpenSSLSymmetricCipher getInstanceChaCha20Poly1305(OpenSSLContext opensslContext,
                                                                     Padding padding) throws OpenSSLException {
        String algName = "chacha20-poly1305";
        return getInstance(opensslContext.isFIPS(), algName, padding);
    }

    public static OpenSSLSymmetricCipher getInstanceAES(OpenSSLContext opensslContext, String mode,
                                                        Padding padding, int numKeyBytes) throws OpenSSLException {
        String algName = "AES-" + Integer.toString(numKeyBytes * 8) + "-" + mode.toUpperCase();
        return getInstance(opensslContext.isFIPS(), algName, padding);
    }

    public static OpenSSLSymmetricCipher getInstanceDESede(OpenSSLContext opensslContext, String mode,
                                                           Padding padding) throws OpenSSLException {
        String modeUpperCase = mode.toUpperCase();
        String algName = modeUpperCase.equals("ECB") ? "DES-EDE3" : "DES-EDE3-" + modeUpperCase;
        return getInstance(opensslContext.isFIPS(), algName, padding);
    }

    private static OpenSSLSymmetricCipher getInstance(boolean isFIPS, String cipherName,
                                                      Padding padding) throws OpenSSLException {
        if (cipherName == null || cipherName.isEmpty()) {
            throw new IllegalArgumentException("cipherName is null/empty");
        }

        if (padding == null) {
            throw new IllegalArgumentException("padding is null");
        }

        return new OpenSSLSymmetricCipher(isFIPS, cipherName, padding);
    }

    static void throwOpenSSLException(int errorCode) throws BadPaddingException, OpenSSLException {
        switch (errorCode) {
            case -1:
                throw new OpenSSLException("OpenSSL_EVP_EncryptUpdate failed!");
            case -2:
                throw new OpenSSLException("OpenSSL_EVP_EncryptFinal failed!");
            case -3:
                throw new OpenSSLException("OpenSSL_EVP_DecryptUpdate failed!");
            case -4:
                throw new OpenSSLException("OpenSSL_EVP_DecryptFinal failed!");
            case -5:
                throw new BadPaddingException("Unexpected padding");
            default:
                throw new OpenSSLException("Unknown Error Code");
        }
    }

    private OpenSSLSymmetricCipher(boolean isFIPS, String cipherName, Padding padding)
            throws OpenSSLException {
        this.isFIPS = isFIPS;
        this.padding = padding;
        // Pass FIPS flag (0=non-FIPS, 1=FIPS)
        int fipsFlag = isFIPS ? 1 : 0;
        this.opensslCipherId = OpenSSLNativeInterface.CIPHER_create(fipsFlag, cipherName);
    }

    public synchronized void initCipherEncrypt(byte[] key, byte[] iv) throws OpenSSLException {
        initCipher(true, key, iv);
    }

    public synchronized void initCipherDecrypt(byte[] key, byte[] iv) throws OpenSSLException {
        initCipher(false, key, iv);
    }

    private void initCipher(boolean isEncrypt, byte[] key, byte[] iv) throws OpenSSLException {
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }
        if ((iv != null) && (iv.length < getIVLength())) {
            throw new IllegalArgumentException("IV is the wrong size");
        }

        if (key.length < getKeyLength()) {
            throw new IllegalArgumentException("key is the wrong size");
        }
        if (opensslCipherId == 0L) {
            throw new OpenSSLException(badIdMsg);
        }

        int fipsFlag = isFIPS ? 1 : 0;
        OpenSSLNativeInterface.CIPHER_init(fipsFlag, opensslCipherId, isEncrypt ? 1 : 0,
                padding.getId(), key, iv);

        this.encrypting = isEncrypt;
        this.bufferedCount = 0;
        this.needsReinit = false;
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

    public int getOutputSize(int inputLen) throws OpenSSLException {
        return getOutputSize(inputLen, true);
    }

    public synchronized int getOutputSize(int inputLen, boolean isFinal) throws OpenSSLException {
        if (inputLen < 0) {
            return 0;
        }
        int totalLen = this.bufferedCount + inputLen;
        int blockSize = getBlockSize();

        // Stream cipher modes (block size = 1) don't use padding
        if (blockSize == 1 || padding == Padding.NoPadding) {
            return totalLen;
        }

        if (!encrypting) {
            return totalLen;
        }
        int retLen = 0;
        int remainderBytes = totalLen % blockSize;
        if (isFinal) {
            retLen = totalLen + (blockSize - remainderBytes);
        } else {
            retLen = totalLen;
        }

        return retLen;
    }

    public synchronized int getBlockSize() throws OpenSSLException {
        if (blockSize == 0) {
            if (opensslCipherId == 0L)
                throw new OpenSSLException(badIdMsg);
            int fipsFlag = isFIPS ? 1 : 0;
            blockSize = OpenSSLNativeInterface.CIPHER_getBlockSize(fipsFlag, opensslCipherId);
        }
        return blockSize;
    }

    public synchronized int getKeyLength() throws OpenSSLException {
        if (keyLength == 0) {
            if (opensslCipherId == 0L) {
                throw new OpenSSLException(badIdMsg);
            }
            int fipsFlag = isFIPS ? 1 : 0;
            keyLength = OpenSSLNativeInterface.CIPHER_getKeyLength(fipsFlag, opensslCipherId);
        }
        return keyLength;
    }

    public synchronized int getIVLength() throws OpenSSLException {
        if (ivLength == 0) {
            if (opensslCipherId == 0L)
                throw new OpenSSLException(badIdMsg);
            int fipsFlag = isFIPS ? 1 : 0;
            ivLength = OpenSSLNativeInterface.CIPHER_getIVLength(fipsFlag, opensslCipherId);
        }
        return ivLength;
    }


    public synchronized int update(byte[] input, int inputOffset, int inputLen, byte[] output,
                                   int outputOffset)
            throws IllegalStateException, ShortBufferException, BadPaddingException, OpenSSLException {
        int outLen = 0;

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (inputLen == 0) {
            return outLen;
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

        // Check if any part of the potential output overlaps the input area.  If so, then make a copy of the input area
        // to work with so that the method is copy-safe.  A copy will be made if the input and output point to the same
        // array and if one of the following conditions is fulfilled:
        //
        //    1. If inputOffset == outputOffset
        //    2. If (inputOffset < outputOffset) and (outputOffset < (inputOffset + inputLen))
        //    3. If (inputOffset > outputOffset) and (inputOffset < (outputOffset + engineGetOutputSize(inputLen)))
        //
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
            int fipsFlag = isFIPS ? 1 : 0;
            if (encrypting) {
                outLen = OpenSSLNativeInterface.CIPHER_encryptUpdate(fipsFlag, opensslCipherId,
                        input, inputOffset, inputLen, output, outputOffset, needsReinit);
            } else {
                outLen = OpenSSLNativeInterface.CIPHER_decryptUpdate(fipsFlag, opensslCipherId,
                        input, inputOffset, inputLen, output, outputOffset, needsReinit);
            }
            if (outLen < 0) {
                throwOpenSSLException(outLen);
            }
            if (outLen > (output.length - outputOffset)) {
                throw new ShortBufferException(
                        "Output buffer must be (at least) " + outLen + " bytes long");
            }

            needsReinit = false;
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }

        this.bufferedCount += inputLen - outLen;
        return outLen;
    }

    public synchronized int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
                                    int outputOffset) throws IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, OpenSSLException {
        int outLen = 0;

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

        // If we are decrypting or if we are encrypting with NoPadding, then
        // total input must be a multiple of the block size.
        // However, stream cipher modes (block size = 1) don't have this restriction.
        //
        int blockSize = getBlockSize();
        if (blockSize > 1 && (!this.encrypting || (this.padding == Padding.NoPadding))) {
            if ((inputLen + bufferedCount) % blockSize != 0) {
                throw new IllegalBlockSizeException(
                        "Input length not multiple of " + blockSize + " bytes");
            }
        }

        int len = getOutputSize(inputLen);

        //Determine if there is anything to do. If the input is nothing and there is nothing to process
        //The skip doing anything and just return with a length of zero and reset stuff for reuse.
        if (len == 0) {
            // All buffered data has been processed. Reset buffered count for future
            // operations
            //
            this.bufferedCount = 0;

            // Need to reset the object such that it can be re-used.
            //
            this.needsReinit = true;
            return len;
        }

        if ((output.length - outputOffset) < len) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        // Check if any part of the potential output overlaps the input area.  If so, then make a copy of a the input area
        // to work with so that the method is copy-safe.  A copy will be made if the input and output point to the same
        // array and if one of the following conditions is fulfilled:
        //
        //    1. If inputOffset == outputOffset
        //    2. If (inputOffset < outputOffset) and (outputOffset < (inputOffset + inputLen))
        //    3. If (inputOffset > outputOffset) and (inputOffset < (outputOffset + engineGetOutputSize(inputLen)))
        //
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
            int fipsFlag = isFIPS ? 1 : 0;
            if (encrypting) {
                outLen = OpenSSLNativeInterface.CIPHER_encryptFinal(fipsFlag, opensslCipherId, input,
                        inputOffset, inputLen, output, outputOffset, needsReinit);
            } else {
                outLen = OpenSSLNativeInterface.CIPHER_decryptFinal(fipsFlag, opensslCipherId, input,
                        inputOffset, inputLen, output, outputOffset, needsReinit);
            }
            if (outLen < 0) {
                throwOpenSSLException(outLen);
            }
            if (outLen > (output.length - outputOffset)) {
                throw new ShortBufferException(
                        "Output buffer must be (at least) " + outLen + " bytes long");
            }
        } catch (OpenSSLException e) {
            throw e;
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }

        // All buffered data has been processed. Reset buffered count for future
        // operations
        //
        this.bufferedCount = 0;

        // Need to reset the object such that it can be re-used.
        //
        this.needsReinit = true;
        return outLen;
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            if (opensslCipherId != 0) {
                int fipsFlag = isFIPS ? 1 : 0;
                OpenSSLNativeInterface.CIPHER_delete(fipsFlag, opensslCipherId);
                opensslCipherId = 0;
            }
        } finally {
            if (reinitKey != null) {
                Arrays.fill(reinitKey, (byte) 0x00);
                reinitKey = null;
            }

            super.finalize();
        }
    }
}
