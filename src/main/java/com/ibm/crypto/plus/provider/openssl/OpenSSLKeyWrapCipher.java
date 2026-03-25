/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

/**
 * OpenSSL-based AES Key Wrap cipher implementation.
 * Supports AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649).
 */
public abstract class OpenSSLKeyWrapCipher extends CipherSpi {

    private OpenSSLContext context;
    private boolean initialized = false;
    private int opmode = 0;
    private byte[] kek = null;  // Key Encryption Key
    private boolean padding = false;
    private int setKeySize = 0;
    private byte[] buffer = null;
    private int bufSize = 0;

    protected OpenSSLKeyWrapCipher(OpenSSLContext context, boolean padding, int keySize) {
        this.context = context;
        this.padding = padding;
        this.setKeySize = keySize;
    }

    private void add2Buffer(byte[] data, int offset, int len) {
        int remain = Integer.MAX_VALUE - bufSize - 16;
        if (len > remain) {
            throw new ProviderException("Buffer can only take " + remain + " more bytes");
        }

        if (buffer == null || buffer.length - bufSize < len) {
            int newSize = Math.addExact(bufSize, len);
            byte[] temp = new byte[newSize];
            if (buffer != null && bufSize > 0) {
                System.arraycopy(buffer, 0, temp, 0, bufSize);
                Arrays.fill(buffer, (byte) 0x00);
            }
            buffer = temp;
        }

        if (data != null) {
            System.arraycopy(data, offset, buffer, bufSize, len);
            bufSize += len;
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("KW") && !mode.equalsIgnoreCase("KWP")) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("Only NoPadding is supported");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 8;  // AES Key Wrap uses 64-bit blocks
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.WRAP_MODE || opmode == Cipher.ENCRYPT_MODE) {
            // Wrapping adds 8 bytes (or rounds up to multiple of 8 for padding mode)
            if (padding) {
                return ((inputLen + 15) / 8) * 8;
            } else {
                return inputLen + 8;
            }
        } else {
            // Unwrapping removes 8 bytes (or may be less for padding mode)
            return Math.max(0, inputLen - 8);
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return null;  // Key Wrap doesn't use IV
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameterSpec not supported");
        }

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        if (!key.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new InvalidKeyException("Key algorithm must be AES");
        }

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        int keyLen = keyBytes.length * 8;
        if (setKeySize != 0 && keyLen != setKeySize) {
            throw new InvalidKeyException(
                    "Key size must be " + setKeySize + " bits, got " + keyLen);
        }

        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw new InvalidKeyException(
                    "Key size must be 128, 192, or 256 bits, got " + keyLen);
        }

        this.opmode = opmode;
        this.kek = keyBytes.clone();
        this.initialized = true;
        this.bufSize = 0;
        if (this.buffer != null) {
            Arrays.fill(this.buffer, (byte) 0x00);
            this.buffer = null;
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameters not supported");
        }
        engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
        add2Buffer(input, inputOffset, inputLen);
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
            throws ShortBufferException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
        add2Buffer(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE &&
                opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new IllegalStateException("Cipher not initialized for encryption/decryption");
        }

        if (input != null && inputLen > 0) {
            add2Buffer(input, inputOffset, inputLen);
        }

        try {
            byte[] result;
            int fipsFlag = context.isFIPS() ? 1 : 0;

            if (opmode == Cipher.WRAP_MODE || opmode == Cipher.ENCRYPT_MODE) {
                result = OpenSSLNativeInterface.KEYWRAP_wrap(
                        fipsFlag, buffer, kek, padding);
            } else {
                result = OpenSSLNativeInterface.KEYWRAP_unwrap(
                        fipsFlag, buffer, kek, padding);
            }

            return result;
        } catch (OpenSSLException e) {
            throw new BadPaddingException("Key wrap/unwrap failed: " + e.getMessage());
        } finally {
            bufSize = 0;
            if (buffer != null) {
                Arrays.fill(buffer, (byte) 0x00);
                buffer = null;
            }
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);

        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException(
                    "Output buffer too small, need " + result.length + " bytes");
        }

        System.arraycopy(result, 0, output, outputOffset, result.length);
        Arrays.fill(result, (byte) 0x00);

        return result.length;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (opmode != Cipher.WRAP_MODE) {
            throw new IllegalStateException("Cipher not initialized for wrapping");
        }

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("Cannot get encoded key");
        }

        try {
            return engineDoFinal(keyBytes, 0, keyBytes.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrapping failed", e);
        } finally {
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                               int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (opmode != Cipher.UNWRAP_MODE) {
            throw new IllegalStateException("Cipher not initialized for unwrapping");
        }

        try {
            byte[] keyBytes = engineDoFinal(wrappedKey, 0, wrappedKey.length);

            if (wrappedKeyType == Cipher.SECRET_KEY) {
                return new javax.crypto.spec.SecretKeySpec(keyBytes, wrappedKeyAlgorithm);
            } else {
                throw new NoSuchAlgorithmException(
                        "Only SECRET_KEY type is supported, got " + wrappedKeyType);
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key is null");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key encoding is null");
        }
        return encoded.length * 8;
    }

    // Public wrapper methods for delegation from AESKeyWrapCipher

    /**
     * Wraps a key using AES Key Wrap.
     *
     * @param plaintext The key material to wrap
     * @param kek The Key Encryption Key
     * @return The wrapped key
     * @throws OpenSSLException if wrapping fails
     */
    public byte[] wrap(byte[] plaintext, byte[] kek) throws OpenSSLException {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("plaintext is null or empty");
        }
        if (kek == null || kek.length == 0) {
            throw new IllegalArgumentException("kek is null or empty");
        }

        int fipsFlag = context.isFIPS() ? 1 : 0;
        return OpenSSLNativeInterface.KEYWRAP_wrap(fipsFlag, plaintext, kek, padding);
    }

    /**
     * Unwraps a key using AES Key Wrap.
     *
     * @param ciphertext The wrapped key material
     * @param kek The Key Encryption Key
     * @return The unwrapped key
     * @throws OpenSSLException if unwrapping fails
     */
    public byte[] unwrap(byte[] ciphertext, byte[] kek) throws OpenSSLException {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("ciphertext is null or empty");
        }
        if (kek == null || kek.length == 0) {
            throw new IllegalArgumentException("kek is null or empty");
        }

        int fipsFlag = context.isFIPS() ? 1 : 0;
        return OpenSSLNativeInterface.KEYWRAP_unwrap(fipsFlag, ciphertext, kek, padding);
    }

    // Concrete implementations for different key sizes and padding modes

    public static final class KW extends OpenSSLKeyWrapCipher {
        public KW(OpenSSLContext context) {
            super(context, false, 0);
        }
    }

    public static final class KWP extends OpenSSLKeyWrapCipher {
        public KWP(OpenSSLContext context) {
            super(context, true, 0);
        }
    }

    public static final class KW_128 extends OpenSSLKeyWrapCipher {
        public KW_128(OpenSSLContext context) {
            super(context, false, 128);
        }
    }

    public static final class KWP_128 extends OpenSSLKeyWrapCipher {
        public KWP_128(OpenSSLContext context) {
            super(context, true, 128);
        }
    }

    public static final class KW_192 extends OpenSSLKeyWrapCipher {
        public KW_192(OpenSSLContext context) {
            super(context, false, 192);
        }
    }

    public static final class KWP_192 extends OpenSSLKeyWrapCipher {
        public KWP_192(OpenSSLContext context) {
            super(context, true, 192);
        }
    }

    public static final class KW_256 extends OpenSSLKeyWrapCipher {
        public KW_256(OpenSSLContext context) {
            super(context, false, 256);
        }
    }

    public static final class KWP_256 extends OpenSSLKeyWrapCipher {
        public KWP_256(OpenSSLContext context) {
            super(context, true, 256);
        }
    }
}

