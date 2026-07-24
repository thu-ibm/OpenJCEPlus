/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;

/**
 * Native method declarations for OpenSSL backend.
 * This class declares all JNI methods that call into the OpenSSL native library.
 *
 * IMPORTANT: All method signatures must exactly match the native C implementations
 * in src/main/native/openssl/*.c files.
 */
public final class NativeOpenSSLImplementation {

    // Debug via system.err only — sun.security.util.Debug is not accessible in the module system
    private static final boolean DEBUG = System.getProperty("java.security.debug", "").contains("jceplus");

    // Default OpenSSL library names (base names, without OS extension).
    // getLibraryFile() appends the correct extension per platform.
    // On Windows: <name>.dll  (OpenSSL ships as libssl-3-x64.dll etc.)
    // On Linux:   <name>.so   (OpenSSL ships as libssl.so etc.)
    // These names include the "lib" prefix because that is the actual file name
    // on all supported platforms (the prefix is part of the file name, not a
    // Unix convention prefix that must be added separately).
    private static final String OPENSSL_LIBRARY_NAME = "libssl-3-x64";
    private static final String CRYPTO_LIBRARY_NAME = "libcrypto-3-x64";
    private static final String JGSKIT_LIBRARY_NAME = "libjgskit_openssl_64";
    private static String osName = null;
    private static String osArch = null;

    static {
        // Initialize OS properties before library loading
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        
        // Preload OpenSSL libraries first
        preloadOpenSSL();
        // Then load our JNI bridge library
        preloadJGskit();
    }

    public static String getOsName() {
        return osName;
    }

    public static String getOsArch() {
        return osArch;
    }

    static String getOpenSSLLoadPath() {
        // For OpenSSL DLLs, check OPENSSL_HOME environment variable first
        String opensslHome = System.getenv("OPENSSL_HOME");
        if (opensslHome != null && !opensslHome.trim().isEmpty()) {
            String opensslPath;
            if (osName.startsWith("Windows")) {
                opensslPath = opensslHome + File.separator + "bin";
            } else {
                opensslPath = opensslHome + File.separator + "lib";
            }
            if (DEBUG) System.err.println("[jceplus] Loading OpenSSL DLLs from OPENSSL_HOME: " + opensslPath);
            return opensslPath;
        }

        // Fall back to openssl.library.path property
        String opensslOverridePath = System.getProperty("openssl.library.path");
        if (opensslOverridePath != null) {
            if (DEBUG) System.err.println("[jceplus] Loading OpenSSL library using value in property openssl.library.path: " + opensslOverridePath);
            return opensslOverridePath;
        }

        if (DEBUG) System.err.println("[jceplus] Library path not found for OpenSSL, use java home directory.");

        String javaHome = System.getProperty("java.home");
        String opensslPath;

        if (osName.startsWith("Windows")) {
            opensslPath = javaHome + File.separator + "bin";
        } else {
            opensslPath = javaHome + File.separator + "lib";
        }

        if (DEBUG) System.err.println("[jceplus] Loading OpenSSL library using value: " + opensslPath);
        return opensslPath;
    }

    static String getJGskitLoadPath() {
        // For our JNI bridge library, check jgskit.library.path property first
        String jgskitOverridePath = System.getProperty("jgskit.library.path");
        if (jgskitOverridePath != null) {
            if (DEBUG) System.err.println("[jceplus] Loading JGskit library using value in property jgskit.library.path: " + jgskitOverridePath);
            return jgskitOverridePath;
        }

        // Fall back to openssl.library.path property
        String opensslOverridePath = System.getProperty("openssl.library.path");
        if (opensslOverridePath != null) {
            if (DEBUG) System.err.println("[jceplus] Loading JGskit library using value in property openssl.library.path: " + opensslOverridePath);
            return opensslOverridePath;
        }
        
        // Fall back to same path as OpenSSL
        return getOpenSSLLoadPath();
    }

    static void preloadOpenSSL() {
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

    static void preloadJGskit() {
        String jgskitPath = getJGskitLoadPath();
        
        File jgskitFile = getLibraryFile(jgskitPath, JGSKIT_LIBRARY_NAME);
        boolean jgskitLoaded = loadIfExists(jgskitFile);
        
        if (!jgskitLoaded) {
            throw new ProviderException("Could not load " + JGSKIT_LIBRARY_NAME + " library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    private static File getLibraryFile(String path, String name) {
        // The library names already contain the "lib" prefix (e.g. "libssl-3-x64"),
        // which is the actual file name on all platforms.  We only need to append
        // the platform-specific extension.
        if (osName.startsWith("Windows")) {
            return new File(path, name + ".dll");
        } else if (osName.equals("Mac OS X")) {
            return new File(path, name + ".dylib");
        } else {
            return new File(path, name + ".so");
        }
    }

    @SuppressWarnings("restricted")
    private static boolean loadIfExists(File libraryFile) {
        String libraryName = libraryFile.getAbsolutePath();

        if (libraryFile.exists()) {
            try {
                System.load(libraryName);
                if (DEBUG) System.err.println("[jceplus] Loaded : " + libraryName);
                return true;
            } catch (UnsatisfiedLinkError e) {
                System.err.println("Failed to load native library: " + libraryName);
                e.printStackTrace(System.err);
                throw e;
            } catch (Error e) {
                // Rethrow serious JVM errors
                throw e;
            } catch (Exception e) {
                System.err.println("Failed to load native library: " + libraryName);
                e.printStackTrace(System.err);
                if (DEBUG) System.err.println("[jceplus] Failed to load : " + libraryName);
            }
        } else {
            if (DEBUG) System.err.println("[jceplus] Skipping load of " + libraryName + " (file does not exist)");
        }
        return false;
    }

    // =========================================================================
    // General functions
    // =========================================================================

    static public native String getLibraryBuildDate();

    // =========================================================================
    // Context functions
    // =========================================================================

    static public native long initializeOpenSSL(boolean isFIPS);
    
    static public native void cleanupOpenSSL(long contextId);

    static public native String CTX_getValue(long contextId, int valueId);

    static native long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Digest functions
    // =========================================================================

    static public native long DIGEST_create(int fipsFlag, String algorithm);

    static public native long DIGEST_copy(int fipsFlag, long digestId);

    static public native int DIGEST_update(int fipsFlag, long digestId, byte[] data,
            int offset, int length);

    static public native byte[] DIGEST_digest(int fipsFlag, long digestId);

    static public native int DIGEST_digest_and_reset(int fipsFlag, long digestId,
            byte[] digest);

    static public native int DIGEST_size(int fipsFlag, long digestId);

    static public native void DIGEST_reset(int fipsFlag, long digestId);

    static public native void DIGEST_delete(int fipsFlag, long digestId);

    // =========================================================================
    // Signature functions
    // =========================================================================

    static public native long SIGNATURE_create(int fipsFlag, byte[] keyBytes,
            int keyLength, String algorithm, int mode);

    static public native int SIGNATURE_update(int fipsFlag, long signatureId,
            byte[] data, int offset, int length);

    static public native byte[] SIGNATURE_sign(int fipsFlag, long signatureId);

    static public native int SIGNATURE_verify(int fipsFlag, long signatureId,
            byte[] signature);

    static public native int SIGNATURE_size(int fipsFlag, long signatureId);

    static public native void SIGNATURE_reset(int fipsFlag, long signatureId);

    static public native int SIGNATURE_setPSSParams(int fipsFlag, long signatureId,
            int saltLen, String mgf1Algorithm);

    static public native void SIGNATURE_delete(int fipsFlag, long signatureId);
    // =========================================================================
    // Key Pair Generation functions
    // =========================================================================

    static public native long KEYPAIRGEN_generateRSA(int fipsFlag, int keySize, long publicExponent);

    static public native long KEYPAIRGEN_generateEC(int fipsFlag, String curveName);

    static public native long KEYPAIRGEN_generateDSA(int fipsFlag, int keySize);

    static public native long KEYPAIRGEN_generateEdDSA(int fipsFlag, String curveName);

    static public native long KEYPAIRGEN_generateDH(int fipsFlag, int primeSize, int generator);

    static public native byte[] KEYPAIRGEN_getPrivateKey(int fipsFlag, long keyPairGenId);

    static public native byte[] KEYPAIRGEN_getPublicKey(int fipsFlag, long keyPairGenId);

    static public native int KEYPAIRGEN_getKeySize(int fipsFlag, long keyPairGenId);

    static public native void KEYPAIRGEN_delete(int fipsFlag, long keyPairGenId);


    // =========================================================================
    // HMAC functions
    // =========================================================================

    static public native long HMAC_create(int fipsFlag, String algorithm);

    static public native int HMAC_init(int fipsFlag, long hmacId, byte[] key, int keyLen);

    static public native int HMAC_update(int fipsFlag, long hmacId, byte[] data,
            int offset, int length);

    static public native int HMAC_doFinal(int fipsFlag, long hmacId, byte[] mac,
            int macOffset);

    static public native int HMAC_size(int fipsFlag, long hmacId);

    static public native void HMAC_reset(int fipsFlag, long hmacId);

    static public native void HMAC_delete(int fipsFlag, long hmacId);

    // =========================================================================
    // HKDF functions
    // =========================================================================

    static public native byte[] HKDF_extract(int fipsFlag, String algorithm, byte[] salt,
            byte[] ikm);

    static public native byte[] HKDF_expand(int fipsFlag, String algorithm, byte[] prk,
            byte[] info, int okmLen);

    static public native byte[] HKDF_derive(int fipsFlag, String algorithm, byte[] salt,
            byte[] ikm, byte[] info, int okmLen);

    // =========================================================================
    // PBKDF2 functions
    // =========================================================================

    static public native byte[] PBKDF2_derive(int fipsFlag, String algorithm, byte[] password,
            byte[] salt, int iterations, int keyLen);

    // =========================================================================
    // Cipher functions
    // =========================================================================

    static public native long CIPHER_create(int fipsFlag, String cipher);

    static public native void CIPHER_init(int fipsFlag, long cipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv);

    static public native int CIPHER_getBlockSize(int fipsFlag, long cipherId);

    static public native int CIPHER_getKeyLength(int fipsFlag, long cipherId);

    static public native int CIPHER_getIVLength(int fipsFlag, long cipherId);

    static public native int CIPHER_encryptUpdate(int fipsFlag, long cipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit);

    static public native int CIPHER_decryptUpdate(int fipsFlag, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit);

    static public native int CIPHER_encryptFinal(int fipsFlag, long cipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit);

    static public native int CIPHER_decryptFinal(int fipsFlag, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit);

    static public native void CIPHER_delete(int fipsFlag, long cipherId);

    // =========================================================================
    // Key Wrap functions
    // =========================================================================

    static public native byte[] KEYWRAP_wrap(int fipsFlag, byte[] plaintext, byte[] kek,
            boolean padding);

    static public native byte[] KEYWRAP_unwrap(int fipsFlag, byte[] wrappedKey, byte[] kek,
            boolean padding);

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    static public native void GCM_init(int fipsFlag, long cipherId, int encrypt,
            byte[] key, byte[] iv, int tagLen);

    static public native int GCM_update(int fipsFlag, long cipherId, int encrypt,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen);

    static public native int GCM_encryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    static public native int GCM_decryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    static public native void CCM_init(int fipsFlag, long cipherId, int encrypt,
            byte[] key, byte[] iv, int tagLen);

    static public native int CCM_update(int fipsFlag, long cipherId, int encrypt,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen);

    static public native int CCM_encryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    static public native int CCM_decryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    // =========================================================================
    // Random Number Generation functions
    // =========================================================================

    /**
     * Generate random bytes using OpenSSL's RAND_bytes().
     *
     * @param isFIPS whether to use FIPS mode (0 = non-FIPS, 1 = FIPS)
     * @param bytes the array to fill with random bytes
     * @throws OpenSSLException if random generation fails
     */
    static public native void RAND_bytes(int isFIPS, byte[] bytes);

    /**
     * Add entropy to OpenSSL's random number generator.
     *
     * @param isFIPS whether to use FIPS mode (0 = non-FIPS, 1 = FIPS)
     * @param seed the seed bytes to add as entropy
     */
    static public native void RAND_seed(int isFIPS, byte[] seed);

    /**
     * Check if the PRNG has been seeded with enough data.
     *
     * @param isFIPS whether to use FIPS mode (0 = non-FIPS, 1 = FIPS)
     * @return 1 if seeded with enough data, 0 otherwise
     */
    static public native int RAND_status(int isFIPS);

    // =========================================================================
    // Extended Random (DRBG) functions
    // =========================================================================

    /**
     * Create a DRBG (Deterministic Random Bit Generator) context.
     * @param isFIPS FIPS mode flag (0 for non-FIPS, 1 for FIPS)
     * @param algName Algorithm name (e.g., "SHA256", "SHA512")
     * @return Context ID (pointer) for the DRBG instance
     */
    static public native long EXTRAND_create(int isFIPS, String algName);

    /**
     * Generate random bytes using the DRBG context.
     * @param isFIPS FIPS mode flag
     * @param drbgContextId Context ID returned by EXTRAND_create
     * @param bytes Output buffer for random bytes
     */
    static public native void EXTRAND_nextBytes(int isFIPS, long drbgContextId, byte[] bytes);

    /**
     * Reseed the DRBG context with additional entropy.
     * @param isFIPS FIPS mode flag
     * @param drbgContextId Context ID returned by EXTRAND_create
     * @param seed Seed data for reseeding
     */
    static public native void EXTRAND_setSeed(int isFIPS, long drbgContextId, byte[] seed);

    /**
     * Delete/free the DRBG context.
     * @param isFIPS FIPS mode flag
     * @param drbgContextId Context ID returned by EXTRAND_create
     */
    static public native void EXTRAND_delete(int isFIPS, long drbgContextId);
}


