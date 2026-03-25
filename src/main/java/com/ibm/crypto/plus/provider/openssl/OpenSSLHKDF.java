/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * OpenSSL-based implementation of HKDF (HMAC-based Key Derivation Function).
 *
 * This class provides a direct interface to OpenSSL's HKDF implementation,
 * offering potential performance benefits over pure Java implementations.
 *
 * HKDF follows RFC 5869 and consists of two phases:
 * 1. Extract: Derives a pseudorandom key (PRK) from input keying material (IKM)
 * 2. Expand: Expands the PRK into the desired output keying material (OKM)
 */
public final class OpenSSLHKDF {

    private final String digestAlgorithm;
    private final int fipsFlag;

    /**
     * Creates a new OpenSSL HKDF instance.
     *
     * @param opensslContext the OpenSSL context
     * @param digestAlgorithm the digest algorithm (e.g., "SHA256", "SHA384", "SHA512")
     * @throws InvalidKeyException if parameters are invalid
     */
    public OpenSSLHKDF(OpenSSLContext opensslContext, String digestAlgorithm)
            throws InvalidKeyException {
        if (opensslContext == null) {
            throw new InvalidKeyException("OpenSSL context cannot be null");
        }
        if (digestAlgorithm == null || digestAlgorithm.isEmpty()) {
            throw new InvalidKeyException("Digest algorithm cannot be null or empty");
        }

        this.digestAlgorithm = digestAlgorithm;
        this.fipsFlag = opensslContext.isFIPS() ? 1 : 0;
    }

    /**
     * Extracts a pseudorandom key from input keying material.
     * This is the first phase of HKDF (HKDF-Extract).
     *
     * @param salt the optional salt value (can be null for default salt)
     * @param ikm the input keying material
     * @return the pseudorandom key (PRK)
     * @throws InvalidKeyException if extraction fails
     */
    public byte[] extract(byte[] salt, byte[] ikm) throws InvalidKeyException {
        if (ikm == null) {
            throw new InvalidKeyException("Input keying material cannot be null");
        }

        try {
            return OpenSSLNativeInterface.HKDF_extract(
                fipsFlag,
                digestAlgorithm,
                salt,
                ikm
            );
        } catch (OpenSSLException e) {
            throw new InvalidKeyException("HKDF extract failed", e);
        }
    }

    /**
     * Expands a pseudorandom key to the desired length.
     * This is the second phase of HKDF (HKDF-Expand).
     *
     * @param prk the pseudorandom key from HKDF-Extract
     * @param info the optional context and application specific information (can be null)
     * @param length the desired output length in bytes
     * @return the output keying material (OKM)
     * @throws InvalidKeyException if expansion fails
     */
    public byte[] expand(byte[] prk, byte[] info, int length) throws InvalidKeyException {
        if (prk == null) {
            throw new InvalidKeyException("Pseudorandom key cannot be null");
        }
        if (length <= 0) {
            throw new InvalidKeyException("Output length must be positive");
        }

        try {
            return OpenSSLNativeInterface.HKDF_expand(
                fipsFlag,
                digestAlgorithm,
                prk,
                info,
                length
            );
        } catch (OpenSSLException e) {
            throw new InvalidKeyException("HKDF expand failed", e);
        }
    }

    /**
     * Derives key material using HKDF (combined extract and expand).
     * This performs both HKDF-Extract and HKDF-Expand in a single operation.
     *
     * @param salt the optional salt value (can be null for default salt)
     * @param ikm the input keying material
     * @param info the optional context and application specific information (can be null)
     * @param length the desired output length in bytes
     * @return the output keying material (OKM)
     * @throws InvalidKeyException if derivation fails
     */
    public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) 
            throws InvalidKeyException {
        if (ikm == null) {
            throw new InvalidKeyException("Input keying material cannot be null");
        }
        if (length <= 0) {
            throw new InvalidKeyException("Output length must be positive");
        }

        try {
            return OpenSSLNativeInterface.HKDF_derive(
                fipsFlag,
                digestAlgorithm,
                salt,
                ikm,
                info,
                length
            );
        } catch (OpenSSLException e) {
            throw new InvalidKeyException("HKDF derive failed", e);
        }
    }

    /**
     * Derives a SecretKey using HKDF.
     *
     * @param salt the optional salt value (can be null for default salt)
     * @param ikm the input keying material
     * @param info the optional context and application specific information (can be null)
     * @param length the desired output length in bytes
     * @param algorithm the algorithm name for the resulting SecretKey
     * @return the derived SecretKey
     * @throws InvalidKeyException if derivation fails
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    public SecretKey deriveKey(byte[] salt, byte[] ikm, byte[] info, int length, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("Algorithm cannot be null or empty");
        }

        byte[] derivedKey = derive(salt, ikm, info, length);
        return new SecretKeySpec(derivedKey, algorithm);
    }

    /**
     * Derives a SecretKey using HKDF with separate extract and expand phases.
     *
     * @param salt the optional salt value (can be null for default salt)
     * @param ikm the input keying material
     * @param info the optional context and application specific information (can be null)
     * @param length the desired output length in bytes
     * @param algorithm the algorithm name for the resulting SecretKey
     * @return the derived SecretKey
     * @throws InvalidKeyException if derivation fails
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    public SecretKey deriveKeyTwoPhase(byte[] salt, byte[] ikm, byte[] info, int length, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("Algorithm cannot be null or empty");
        }

        // Phase 1: Extract
        byte[] prk = extract(salt, ikm);

        // Phase 2: Expand
        byte[] okm = expand(prk, info, length);

        return new SecretKeySpec(okm, algorithm);
    }

    /**
     * Gets the digest algorithm name.
     *
     * @return the digest algorithm name
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Checks if this instance is using FIPS mode.
     *
     * @return true if FIPS mode is enabled
     */
    public boolean isFIPS() {
        return fipsFlag == 1;
    }

    /**
     * Gets the maximum output length for this HKDF instance.
     * According to RFC 5869, the maximum output length is 255 * HashLen.
     *
     * @return the maximum output length in bytes
     */
    public int getMaxOutputLength() {
        // Get hash length based on digest algorithm
        int hashLen;
        switch (digestAlgorithm) {
            case "SHA256":
                hashLen = 32;
                break;
            case "SHA384":
                hashLen = 48;
                break;
            case "SHA512":
                hashLen = 64;
                break;
            case "SHA224":
                hashLen = 28;
                break;
            case "SHA1":
                hashLen = 20;
                break;
            default:
                // Default to SHA256 length
                hashLen = 32;
        }
        return 255 * hashLen;
    }
}


