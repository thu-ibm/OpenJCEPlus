/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * OpenSSL-based implementation of PBKDF2 (Password-Based Key Derivation Function 2).
 *
 * This class provides a direct interface to OpenSSL's PBKDF2 implementation,
 * offering potential performance benefits over pure Java implementations.
 */
public final class OpenSSLPBKDF2 {

    private final String prfAlgorithm;
    private final int fipsFlag;

    /**
     * Creates a new OpenSSL PBKDF2 instance.
     *
     * @param opensslContext the OpenSSL context
     * @param prfAlgorithm the PRF algorithm (e.g., "HmacSHA256", "HmacSHA512")
     * @throws InvalidKeyException if parameters are invalid
     */
    public OpenSSLPBKDF2(OpenSSLContext opensslContext, String prfAlgorithm)
            throws InvalidKeyException {
        if (opensslContext == null) {
            throw new InvalidKeyException("OpenSSL context cannot be null");
        }
        if (prfAlgorithm == null || prfAlgorithm.isEmpty()) {
            throw new InvalidKeyException("PRF algorithm cannot be null or empty");
        }

        this.prfAlgorithm = prfAlgorithm;
        this.fipsFlag = opensslContext.isFIPS() ? 1 : 0;
    }

    /**
     * Derives a key using PBKDF2.
     *
     * @param keySpec the PBE key specification containing password, salt, iterations, and key length
     * @return the derived secret key
     * @throws InvalidKeySpecException if the key specification is invalid or derivation fails
     */
    public SecretKey deriveKey(PBEKeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("PBEKeySpec cannot be null");
        }

        char[] password = keySpec.getPassword();
        if (password == null) {
            throw new InvalidKeySpecException("Password cannot be null");
        }

        byte[] salt = keySpec.getSalt();
        if (salt == null) {
            throw new InvalidKeySpecException("Salt cannot be null");
        }

        int iterationCount = keySpec.getIterationCount();
        if (iterationCount <= 0) {
            throw new InvalidKeySpecException("Iteration count must be positive");
        }

        int keyLength = keySpec.getKeyLength();
        if (keyLength <= 0) {
            throw new InvalidKeySpecException("Key length must be positive");
        }

        // Convert password to bytes (UTF-8)
        byte[] passwordBytes = convertPasswordToBytes(password);

        try {
            // Extract digest algorithm name from PRF algorithm
            // e.g., "HmacSHA256" -> "SHA256"
            String digestAlgo = extractDigestAlgorithm(prfAlgorithm);

            // Derive key using OpenSSL
            byte[] derivedKey = OpenSSLNativeInterface.PBKDF2_derive(
                fipsFlag,
                digestAlgo,
                passwordBytes,
                salt,
                iterationCount,
                keyLength / 8  // Convert bits to bytes
            );

            // Create SecretKey
            return new SecretKeySpec(derivedKey, "PBKDF2With" + prfAlgorithm);

        } catch (OpenSSLException e) {
            throw new InvalidKeySpecException("PBKDF2 key derivation failed", e);
        } finally {
            // Clear sensitive data
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    /**
     * Converts a character array password to UTF-8 bytes.
     *
     * @param password the password characters
     * @return the UTF-8 encoded password bytes
     */
    private byte[] convertPasswordToBytes(char[] password) {
        // Convert char[] to UTF-8 bytes
        byte[] passwordBytes = new byte[password.length * 3]; // Max UTF-8 bytes per char
        int length = 0;
        
        for (char c : password) {
            if (c < 0x80) {
                // ASCII character (1 byte)
                passwordBytes[length++] = (byte) c;
            } else if (c < 0x800) {
                // 2-byte UTF-8
                passwordBytes[length++] = (byte) (0xC0 | (c >> 6));
                passwordBytes[length++] = (byte) (0x80 | (c & 0x3F));
            } else {
                // 3-byte UTF-8
                passwordBytes[length++] = (byte) (0xE0 | (c >> 12));
                passwordBytes[length++] = (byte) (0x80 | ((c >> 6) & 0x3F));
                passwordBytes[length++] = (byte) (0x80 | (c & 0x3F));
            }
        }
        
        // Trim to actual length
        return Arrays.copyOf(passwordBytes, length);
    }

    /**
     * Extracts the digest algorithm name from the PRF algorithm name.
     *
     * @param prfAlgorithm the PRF algorithm (e.g., "HmacSHA256")
     * @return the digest algorithm (e.g., "SHA256")
     * @throws InvalidKeySpecException if the PRF algorithm is not supported
     */
    private String extractDigestAlgorithm(String prfAlgorithm) throws InvalidKeySpecException {
        if (prfAlgorithm.startsWith("Hmac")) {
            return prfAlgorithm.substring(4); // Remove "Hmac" prefix
        }
        throw new InvalidKeySpecException("Unsupported PRF algorithm: " + prfAlgorithm);
    }

    /**
     * Gets the PRF algorithm name.
     *
     * @return the PRF algorithm name
     */
    public String getPRFAlgorithm() {
        return prfAlgorithm;
    }

    /**
     * Checks if this instance is using FIPS mode.
     *
     * @return true if FIPS mode is enabled
     */
    public boolean isFIPS() {
        return fipsFlag == 1;
    }
}


