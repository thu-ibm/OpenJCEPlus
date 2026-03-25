/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import sun.security.util.Debug;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;

final class OpenSSLNativeInterface {

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    // Whether OpenSSL is dynamically loaded
    private static final boolean opensslDynamicallyLoaded = true;

    // Default OpenSSL library names
    private static final String OPENSSL_LIBRARY_NAME = "libssl-3-x64";
    private static final String CRYPTO_LIBRARY_NAME = "libcrypto-3-x64";
    private static final String JGSKIT_CORE_LIBRARY_NAME = "jgskit_openssl";

    private static String osName = null;
    private static String osArch = null;

    static {
        if (opensslDynamicallyLoaded) {
            // Preload OpenSSL libraries
            preloadOpenSSL();
        }
        // Load native code for java-openssl bridge
        preloadJGskit();
    }

    public static String getOsName() {
        return osName;
    }

    public static String getOsArch() {
        return osArch;

    }

    static String getOpenSSLLoadPath() {
        String opensslOverridePath = System.getProperty("openssl.library.path");
        if (opensslOverridePath != null) {
            if (debug != null) {
                debug.println("Loading OpenSSL library using value in property openssl.library.path: "
                        + opensslOverridePath);
            }
            return opensslOverridePath;
        }
        if (debug != null) {
            debug.println("Library path not found for OpenSSL, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String opensslPath;

        if (osName.startsWith("Windows")) {
            opensslPath = javaHome + File.separator + "bin";
        } else {
            opensslPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading OpenSSL library using value: " + opensslPath);
        }
        return opensslPath;
    }

    static void preloadOpenSSL() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String opensslPath = getOpenSSLLoadPath();

        File cryptoFile = getLibraryFile(opensslPath, CRYPTO_LIBRARY_NAME);
        File sslFile = getLibraryFile(opensslPath, OPENSSL_LIBRARY_NAME);

        boolean cryptoLoaded = loadIfExists(cryptoFile);
        boolean sslLoaded = loadIfExists(sslFile);

        if (!cryptoLoaded || !sslLoaded) {
            throw new ProviderException("Could not load OpenSSL libraries for os.name=" + osName
                    + ", os.arch=" + osArch);
        }
    }

    /**
     * Gets the library file for the given path and name.
     *
     * @param path the path to the library
     * @param name the name of the library
     * @return the library file
     */
    private static File getLibraryFile(String path, String name) {
        if (osName.startsWith("Windows")) {
            // For OpenSSL v3, the library names already include the "lib" prefix and ".dll" suffix
            if (name.startsWith("lib") && (name.endsWith("-x64") || name.endsWith("-x86"))) {
                return new File(path, name + ".dll");
            } else {
                return new File(path, "lib" + name + ".dll");
            }
        } else if (osName.equals("Mac OS X")) {
            // For Mac, ensure the "lib" prefix is present
            if (name.startsWith("lib")) {
                return new File(path, name + ".dylib");
            } else {
                return new File(path, "lib" + name + ".dylib");
            }
        } else {
            // For Linux, ensure the "lib" prefix is present
            if (name.startsWith("lib")) {
                return new File(path, name + ".so");
            } else {
                return new File(path, "lib" + name + ".so");
            }
        }
    }

    static String getJGskitLoadPath() {
        String jgskitOverridePath = System.getProperty("jgskit.library.path");

        if (jgskitOverridePath != null) {
            if (debug != null) {
                debug.println("Loading jgskit library using value in property jgskit.library.path: " + jgskitOverridePath);
            }
            return jgskitOverridePath;
        }
        if (debug != null) {
            debug.println("Libpath not found for jgskit, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String jgskitPath;

        if (osName.startsWith("Windows")) {
            jgskitPath = javaHome + File.separator + "bin";
        } else {
            jgskitPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading jgskit library using value: " + jgskitPath);
        }
        return jgskitPath;
    }

    static void preloadJGskit() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String jgskitPath = getJGskitLoadPath();

        System.out.println("preloadJGskit():" + jgskitPath);
        File loadFile = null;
        if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + "_64.dll");
        } else if (osName.equals("Mac OS X")) {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + ".dylib");
        } else {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + ".so");
        }

        boolean jgskitLibraryPreloaded = loadIfExists(loadFile);
        if (jgskitLibraryPreloaded == false) {
            throw new ProviderException("Could not load dependent " + JGSKIT_CORE_LIBRARY_NAME + " library for os.name=" + osName
                    + ", os.arch=" + osArch);
        }
    }

    private static boolean loadIfExists(File libraryFile) {
        String libraryName = libraryFile.getAbsolutePath();

        if (libraryFile.exists()) {
            try {
                System.load(libraryName);
                if (debug != null) {
                    debug.println("Loaded : " + libraryName);
                }
                return true;
            } catch (Throwable t) {
                if (debug != null) {
                    debug.println("Failed to load : " + libraryName);
                }
            }
        } else {
            if (debug != null) {
                debug.println("Skipping load of " + libraryName);
            }
        }
        return false;
    }

    /**
     * Validates the OpenSSL library location.
     *
     * @param context the OpenSSL context
     * @throws ProviderException if the library location is invalid
     * @throws OpenSSLException if an OpenSSL error occurs
     */
//    static void validateLibraryLocation(OpenSSLContext context) throws ProviderException, OpenSSLException {
//        try {
//            // Check to make sure that the OpenSSL install path is within the JRE
//            String opensslLoadPath = new File(getOpenSSLLoadPath()).getCanonicalPath();
//            String opensslInstallPath = new File(context.getOpenSSLInstallPath()).getCanonicalPath();
//
//            if (debug != null) {
//                debug.println("OpenSSL library load path : " + opensslLoadPath);
//                debug.println("OpenSSL library install path : " + opensslInstallPath);
//            }
//
//            if (!opensslInstallPath.startsWith(opensslLoadPath)) {
//                String exceptionMessage = "OpenSSL library was loaded from an external location";
//
//                if (debug != null) {
//                    exceptionMessage = "OpenSSL library was loaded from " + opensslInstallPath;
//                }
//
//                throw new ProviderException(exceptionMessage);
//            }
//        } catch (java.io.IOException e) {
//            throw new ProviderException("Failed to validate OpenSSL library", e);
//        }
//    }

    /**
     * Validates the OpenSSL library version.
     *
     * @param context the OpenSSL context
     * @throws ProviderException if the library version is invalid
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static void validateLibraryVersion(OpenSSLContext context) throws ProviderException, OpenSSLException {
        // For now, we'll just check that we can get the version
        String version = context.getOpenSSLVersion();
        if (version == null || version.isEmpty()) {
            throw new ProviderException("Could not determine OpenSSL library version");
        }

        if (debug != null) {
            debug.println("OpenSSL library version: " + version);
        }
    }

    // =========================================================================
    // Native method for OpenSSL
    // =========================================================================

    static public native String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    static public native long initializeOpenSSL(boolean isFIPS) throws OpenSSLException;

    static public native String CTX_getValue(long opensslContextId, int valueId) throws OpenSSLException;

    static native long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    static public native void RAND_nextBytes(long opensslContextId, byte[] buffer) throws OpenSSLException;

    static public native void RAND_setSeed(long opensslContextId, byte[] seed) throws OpenSSLException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    static public native long CIPHER_create(long opensslContextId, String cipherName) throws OpenSSLException;

    static public native void CIPHER_init(long opensslContextId, long cipherId, int encrypt,
                                          int paddingId, byte[] key, byte[] iv) throws OpenSSLException;

    static public native int CIPHER_getBlockSize(long opensslContextId, long cipherId) throws OpenSSLException;

    static public native int CIPHER_getKeyLength(long opensslContextId, long cipherId) throws OpenSSLException;

    static public native int CIPHER_getIVLength(long opensslContextId, long cipherId) throws OpenSSLException;

    static public native int CIPHER_encryptUpdate(long opensslContextId, long cipherId,
                                                  byte[] input, int inputOffset, int inputLen,
                                                  byte[] output, int outputOffset,
                                                  boolean needsReinit) throws OpenSSLException;

    static public native int CIPHER_decryptUpdate(long opensslContextId, long cipherId,
                                                  byte[] input, int inputOffset, int inputLen,
                                                  byte[] output, int outputOffset,
                                                  boolean needsReinit) throws OpenSSLException;

    static public native int CIPHER_encryptFinal(long opensslContextId, long cipherId,
                                                 byte[] input, int inputOffset, int inputLen,
                                                 byte[] output, int outputOffset,
                                                 boolean needsReinit) throws OpenSSLException;

    static public native int CIPHER_decryptFinal(long opensslContextId, long cipherId,
                                                 byte[] input, int inputOffset, int inputLen,
                                                 byte[] output, int outputOffset,
                                                 boolean needsReinit) throws OpenSSLException;

    static public native void CIPHER_delete(long opensslContextId, long cipherId) throws OpenSSLException;


    // GCM-specific functions
    /**
     * Initializes a GCM cipher context.
     *
     * @param opensslContextId the OpenSSL context ID
     * @param cipherId the cipher context ID
     * @param encrypt whether to encrypt (1) or decrypt (0)
     * @param key the key
     * @param iv the initialization vector
     * @param tagLen the authentication tag length
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native void GCM_init(long opensslContextId, long cipherId, int encrypt,
                                       byte[] key, byte[] iv, int tagLen) throws OpenSSLException;

    /**
     * Updates a GCM cipher context.
     *
     * @param opensslContextId the OpenSSL context ID
     * @param cipherId the cipher context ID
     * @param encrypt whether encrypting (1) or decrypting (0)
     * @param input the input data
     * @param inputOffset the offset into the input data
     * @param inputLen the length of the input data
     * @param output the output buffer
     * @param outputOffset the offset into the output buffer
     * @param aad the additional authenticated data (can be null)
     * @param aadLen the length of the AAD
     * @return the number of bytes written to the output buffer
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int GCM_update(long opensslContextId, long cipherId, int encrypt,
                                        byte[] input, int inputOffset, int inputLen,
                                        byte[] output, int outputOffset,
                                        byte[] aad, int aadLen) throws OpenSSLException;

    /**
     * Finalizes a GCM cipher context.
     * For encryption, this appends the authentication tag to the output.
     * For decryption, this verifies the authentication tag.
     *
     * @param opensslContextId the OpenSSL context ID
     * @param cipherId the cipher context ID
     * @param input the input data
     * @param inputOffset the offset into the input data
     * @param inputLen the length of the input data
     * @param output the output buffer
     * @param outputOffset the offset into the output buffer
     * @param aad the additional authenticated data
     * @param aadLen the length of the AAD
     * @param tagLen the authentication tag length
     * @return the number of bytes written to the output buffer (including tag)
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int GCM_encryptFinal(long opensslContextId, long cipherId,
                                              byte[] input, int inputOffset, int inputLen,
                                              byte[] output, int outputOffset,
                                              byte[] aad, int aadLen, int tagLen) throws OpenSSLException;

    /**
     * Finalizes a GCM decryption operation.
     *
     * @param opensslContextId the OpenSSL context ID (or FIPS flag: 0=non-FIPS, 1=FIPS)
     * @param cipherId the cipher context ID
     * @param input the input buffer containing ciphertext and authentication tag
     * @param inputOffset the offset in the input buffer
     * @param inputLen the length of input data (ciphertext + tag)
     * @param output the output buffer for plaintext
     * @param outputOffset the offset in the output buffer
     * @param aad the additional authenticated data (AAD)
     * @param aadLen the length of the AAD
     * @param tagLen the authentication tag length
     * @return the number of bytes written to the output buffer (plaintext only)
     * @throws OpenSSLException if an OpenSSL error occurs or tag verification fails
     */
    static public native int GCM_decryptFinal(long opensslContextId, long cipherId,
                                              byte[] input, int inputOffset, int inputLen,
                                              byte[] output, int outputOffset,
                                              byte[] aad, int aadLen, int tagLen) throws OpenSSLException;

    // CCM-specific functions
    /**
     * Initializes a CCM cipher context.
     *
     * @param opensslContextId the OpenSSL context ID (or FIPS flag: 0=non-FIPS, 1=FIPS)
     * @param cipherId the cipher context ID
     * @param encrypt whether to encrypt (1) or decrypt (0)
     * @param key the key
     * @param iv the initialization vector (nonce)
     * @param tagLen the authentication tag length in bytes
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native void CCM_init(long opensslContextId, long cipherId, int encrypt,
                                       byte[] key, byte[] iv, int tagLen) throws OpenSSLException;

    /**
     * Updates a CCM cipher context.
     *
     * @param opensslContextId the OpenSSL context ID (or FIPS flag: 0=non-FIPS, 1=FIPS)
     * @param cipherId the cipher context ID
     * @param encrypt whether encrypting (1) or decrypting (0)
     * @param input the input data
     * @param inputOffset the offset into the input data
     * @param inputLen the length of the input data
     * @param output the output buffer
     * @param outputOffset the offset into the output buffer
     * @param aad the additional authenticated data (can be null)
     * @param aadLen the length of the AAD
     * @return the number of bytes written to the output buffer
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int CCM_update(long opensslContextId, long cipherId, int encrypt,
                                        byte[] input, int inputOffset, int inputLen,
                                        byte[] output, int outputOffset,
                                        byte[] aad, int aadLen) throws OpenSSLException;

    /**
     * Finalizes a CCM encryption operation and generates the authentication tag.
     *
     * @param opensslContextId the OpenSSL context ID (or FIPS flag: 0=non-FIPS, 1=FIPS)
     * @param cipherId the cipher context ID
     * @param input the input buffer containing plaintext
     * @param inputOffset the offset in the input buffer
     * @param inputLen the length of input data
     * @param output the output buffer for ciphertext and authentication tag
     * @param outputOffset the offset in the output buffer
     * @param aad the additional authenticated data (AAD)
     * @param aadLen the length of the AAD
     * @param tagLen the authentication tag length
     * @return the number of bytes written to the output buffer (ciphertext + tag)
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int CCM_encryptFinal(long opensslContextId, long cipherId,
                                              byte[] input, int inputOffset, int inputLen,
                                              byte[] output, int outputOffset,
                                              byte[] aad, int aadLen, int tagLen) throws OpenSSLException;

    /**
     * Finalizes a CCM decryption operation and verifies the authentication tag.
     *
     * @param opensslContextId the OpenSSL context ID (or FIPS flag: 0=non-FIPS, 1=FIPS)
     * @param cipherId the cipher context ID
     * @param input the input buffer containing ciphertext and authentication tag
     * @param inputOffset the offset in the input buffer
     * @param inputLen the length of input data (ciphertext + tag)
     * @param output the output buffer for plaintext
     * @param outputOffset the offset in the output buffer
     * @param aad the additional authenticated data (AAD)
     * @param aadLen the length of the AAD
     * @param tagLen the authentication tag length
     * @return the number of bytes written to the output buffer (plaintext only)
     * @throws OpenSSLException if an OpenSSL error occurs or tag verification fails
     */
    static public native int CCM_decryptFinal(long opensslContextId, long cipherId,
                                              byte[] input, int inputOffset, int inputLen,
                                              byte[] output, int outputOffset,
                                              byte[] aad, int aadLen, int tagLen) throws OpenSSLException;

    // =========================================================================
    // Digest (Message Digest/Hash) functions
    // =========================================================================

    /**
     * Creates a new digest context for the specified algorithm.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestAlgo the digest algorithm name (e.g., "SHA-256", "SHA3-512")
     * @return the digest context ID
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native long DIGEST_create(int fipsFlag, String digestAlgo) throws OpenSSLException;

    /**
     * Creates a copy of an existing digest context.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the source digest context ID
     * @return the new digest context ID (copy)
     * @throws OpenSSLException if an OpenSSLError occurs
     */
    static public native long DIGEST_copy(int fipsFlag, long digestId) throws OpenSSLException;

    /**
     * Updates the digest with additional data.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the digest context ID
     * @param data the input data to hash
     * @param offset the offset in the data array
     * @param dataLen the length of data to process
     * @return 1 on success, negative error code on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int DIGEST_update(int fipsFlag, long digestId,
                                           byte[] data, int offset, int dataLen) throws OpenSSLException;

    /**
     * Finalizes the digest and returns the hash value.
     * The digest context is automatically reset after this operation.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the digest context ID
     * @return the digest hash as a byte array
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] DIGEST_digest(int fipsFlag, long digestId) throws OpenSSLException;

    /**
     * Finalizes the digest, stores result in provided array, and resets for reuse.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the digest context ID
     * @param output the output array to store the digest
     * @return 1 on success, negative error code on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int DIGEST_digest_and_reset(int fipsFlag, long digestId,
                                                     byte[] output) throws OpenSSLException;

    /**
     * Gets the size of the digest output in bytes.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the digest context ID
     * @return the digest size in bytes
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int DIGEST_size(int fipsFlag, long digestId) throws OpenSSLException;

    /**
     * Resets the digest context to its initial state.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the digest context ID
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native void DIGEST_reset(int fipsFlag, long digestId) throws OpenSSLException;

    /**
     * Deletes the digest context and frees associated resources.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestId the digest context ID to delete
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native void DIGEST_delete(int fipsFlag, long digestId) throws OpenSSLException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    /**
     * Creates a new HMAC context for the specified digest algorithm.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestAlgo the digest algorithm name (e.g., "SHA-256", "SHA-512")
     * @return HMAC context ID, or 0 on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native long HMAC_create(int fipsFlag, String digestAlgo) throws OpenSSLException;

    /**
     * Initializes HMAC context with a secret key.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param hmacId HMAC context ID
     * @param key the secret key
     * @param keyLen length of the key
     * @return 1 on success, negative error code on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int HMAC_init(int fipsFlag, long hmacId,
                                       byte[] key, int keyLen) throws OpenSSLException;

    /**
     * Updates the HMAC with additional data.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param hmacId HMAC context ID
     * @param data input data to process
     * @param offset offset in the data array
     * @param dataLen length of data to process
     * @return 1 on success, negative error code on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int HMAC_update(int fipsFlag, long hmacId,
                                         byte[] data, int offset, int dataLen) throws OpenSSLException;

    /**
     * Finalizes the HMAC, stores result in provided array, and resets for reuse.
     * This matches the OCK pattern and OpenSSL's native API design.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param hmacId HMAC context ID
     * @param output pre-allocated output array to store the HMAC (must be at least macSize bytes)
     * @return 1 on success, -1 on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int HMAC_doFinal(int fipsFlag, long hmacId, byte[] output) throws OpenSSLException;

    /**
     * Gets the size of the HMAC output in bytes.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param hmacId HMAC context ID
     * @return size of HMAC in bytes, or negative error code on failure
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native int HMAC_size(int fipsFlag, long hmacId) throws OpenSSLException;

    /**
     * Resets the HMAC context to its initial state.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param hmacId HMAC context ID
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native void HMAC_reset(int fipsFlag, long hmacId) throws OpenSSLException;

    /**
     * Deletes the HMAC context and frees associated resources.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param hmacId HMAC context ID to delete
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native void HMAC_delete(int fipsFlag, long hmacId) throws OpenSSLException;

    // =========================================================================
    // PBKDF2 functions
    // =========================================================================

    /**
     * Derives a key using PBKDF2 (Password-Based Key Derivation Function 2).
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestAlgo the digest algorithm name (e.g., "SHA256", "SHA512")
     * @param password the password bytes
     * @param salt the salt bytes
     * @param iterations the iteration count
     * @param keyLength the desired key length in bytes
     * @return the derived key bytes
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] PBKDF2_derive(int fipsFlag, String digestAlgo,
                                              byte[] password, byte[] salt,
                                              int iterations, int keyLength) throws OpenSSLException;

    // =========================================================================
    // HKDF functions
    // =========================================================================

    /**
     * Extracts a pseudorandom key from input keying material using HKDF-Extract.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestAlgo the digest algorithm name (e.g., "SHA256", "SHA512")
     * @param salt the optional salt value (can be null)
     * @param ikm the input keying material
     * @return the pseudorandom key (PRK)
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] HKDF_extract(int fipsFlag, String digestAlgo,
                                             byte[] salt, byte[] ikm) throws OpenSSLException;

    /**
     * Expands a pseudorandom key to the desired length using HKDF-Expand.
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestAlgo the digest algorithm name (e.g., "SHA256", "SHA512")
     * @param prk the pseudorandom key from HKDF-Extract
     * @param info the optional context and application specific information (can be null)
     * @param length the desired output length in bytes
     * @return the output keying material (OKM)
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] HKDF_expand(int fipsFlag, String digestAlgo,
                                            byte[] prk, byte[] info, int length) throws OpenSSLException;

    /**
     * Derives key material using HKDF (combined extract and expand).
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param digestAlgo the digest algorithm name (e.g., "SHA256", "SHA512")
     * @param salt the optional salt value (can be null)
     * @param ikm the input keying material
     * @param info the optional context and application specific information (can be null)
     * @param length the desired output length in bytes
     * @return the output keying material (OKM)
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] HKDF_derive(int fipsFlag, String digestAlgo,
                                            byte[] salt, byte[] ikm, byte[] info, int length) throws OpenSSLException;

    // =========================================================================
    // Key Wrap functions
    // =========================================================================

    /**
     * Wraps a key using AES Key Wrap algorithm (RFC 3394) or AES Key Wrap with Padding (RFC 5649).
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param plaintext the key material to wrap
     * @param kek the key encryption key
     * @param padding whether to use padding (true for KWP, false for KW)
     * @return the wrapped key
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] KEYWRAP_wrap(int fipsFlag, byte[] plaintext,
                                             byte[] kek, boolean padding) throws OpenSSLException;

    /**
     * Unwraps a key using AES Key Wrap algorithm (RFC 3394) or AES Key Wrap with Padding (RFC 5649).
     *
     * @param fipsFlag FIPS mode flag (0=non-FIPS, 1=FIPS)
     * @param ciphertext the wrapped key
     * @param kek the key encryption key
     * @param padding whether to use padding (true for KWP, false for KW)
     * @return the unwrapped key material
     * @throws OpenSSLException if an OpenSSL error occurs
     */
    static public native byte[] KEYWRAP_unwrap(int fipsFlag, byte[] ciphertext,
                                               byte[] kek, boolean padding) throws OpenSSLException;
}

