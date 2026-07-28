/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeInterface;
import sun.security.util.Debug;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;

public abstract class NativeOpenSSLAdapter implements NativeInterface {
    // These code values must match those defined in OpenSSLContext.h
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OPENSSL_VERSION = 1;
    private static final int VALUE_OPENSSL_INSTALL_PATH = 2;

    // FIPS flag constants for native calls
    private static final int FIPS_ENABLED = 1;
    private static final int FIPS_DISABLED = 0;

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    static final String unobtainedValue = new String();
    
    // EC Key storage for OpenSSL backend
    // Maps key ID to key bytes (PKCS#8 for private, X.509 for public)
    private final java.util.concurrent.ConcurrentHashMap<Long, byte[]> ecKeyStore =
        new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicLong ecKeyIdCounter =
        new java.util.concurrent.atomic.AtomicLong(1);

    // whether to validate OpenSSL was loaded from JRE location
    // Can be enabled via system property for production deployments
    private static final boolean validateOpenSSLLocation =
        Boolean.getBoolean("openssl.enable.location.validation");

    private OpenSSLContext opensslContext = null;
    private boolean opensslInitialized = false;
    private final boolean fipsMode;

    private String opensslVersion = unobtainedValue;
    private String opensslInstallPath = unobtainedValue;

    private static String libraryBuildDate = unobtainedValue;
    private static final int DEFAULT_GCM_TAG_LEN = 16;
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private static final long HKDF_DUMMY_CONTEXT_ID = 1L;

    NativeOpenSSLAdapter(boolean fipsMode) {
        this.fipsMode = fipsMode;
        initializeContext();
    }

    // Initialize OpenSSL context
    private synchronized void initializeContext() {
        if (opensslInitialized) {
            return;
        }

        try {
            long opensslContextId = NativeOpenSSLImplementation.initializeOpenSSL(this.fipsMode);
            this.opensslContext = OpenSSLContext.createContext(opensslContextId, this.fipsMode);
            getLibraryBuildDate();

            if (validateOpenSSLLocation) {
                validateLibraryLocation();
            }

            this.opensslInitialized = true;
        } catch (OpenSSLException e) {
            throw providerException("Failed to initialize OpenJCEPlus provider with OpenSSL", e);
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlus provider with OpenSSL", t);

            if (exceptionToThrow.getCause() == null) {
                if ((t instanceof ExceptionInInitializerError)
                        || (t instanceof NoClassDefFoundError)) {
                    Throwable cause = t.getCause();
                    if (cause != null) {
                        t = cause;
                    }
                }

                String message = t.getMessage();
                if ((message != null) && (message.length() > 0)) {
                    exceptionToThrow.initCause(new ProviderException(t.getMessage()));
                }
            }

            if (debug != null) {
                exceptionToThrow.printStackTrace(System.out);
            }

            throw exceptionToThrow;
        }
    }

    // Get OpenSSL context for crypto operations
    OpenSSLContext getOpenSSLContext() {
        if (!opensslInitialized) {
            initializeContext();
        }
        return opensslContext;
    }

    @Override
    public String getLibraryVersion() throws OpenSSLException {
        if (opensslVersion == unobtainedValue) {
            obtainOpenSSLVersion();
        }
        return opensslVersion;
    }

    @Override
    public String getLibraryInstallPath() throws OpenSSLException {
        if (opensslInstallPath == unobtainedValue) {
            obtainOpenSSLInstallPath();
        }
        return opensslInstallPath;
    }

    private synchronized void obtainOpenSSLVersion() throws OpenSSLException {
        if (opensslVersion == unobtainedValue) {
            opensslVersion = CTX_getValue(VALUE_OPENSSL_VERSION);
        }
    }

    private synchronized void obtainOpenSSLInstallPath() throws OpenSSLException {
        if (opensslInstallPath == unobtainedValue) {
            opensslInstallPath = CTX_getValue(VALUE_OPENSSL_INSTALL_PATH);
        }
    }

    static public ProviderException providerException(String message, Throwable opensslException) {
        ProviderException providerException = new ProviderException(message, opensslException);
        setOpenSSLExceptionCause(providerException, opensslException);
        return providerException;
    }

    static public void setOpenSSLExceptionCause(Exception exception, Throwable opensslException) {
        if (exception.getCause() == null) {
            exception.initCause(opensslException);
        }
    }
    
    // Get FIPS flag for native calls
    private int getFipsFlag() {
        return this.fipsMode ? FIPS_ENABLED : FIPS_DISABLED;
    }

    @Override
    public void validateLibraryLocation() throws ProviderException, OpenSSLException {
        // Skip validation if disabled via system property
        if (!validateOpenSSLLocation) {
            return;
        }
        
        try {
            String opensslLoadPath = new File(NativeOpenSSLImplementation.getOpenSSLLoadPath()).getCanonicalPath();
            String opensslInstallPath = new File(getLibraryInstallPath()).getCanonicalPath();
            if (!opensslInstallPath.startsWith(opensslLoadPath)) {
                throw new ProviderException("OpenSSL library was loaded from an external location: "
                    + opensslInstallPath + " (expected under: " + opensslLoadPath + ")");
            }
        } catch (java.io.IOException e) {
            throw new ProviderException("Failed to validate OpenSSL library location", e);
        }
    }

    @Override
    public void validateLibraryVersion() throws ProviderException, OpenSSLException {
        // OpenSSL version validation can be added here if needed
        // For now, we skip this as OpenSSL doesn't have ICCSIG.txt equivalent
    }

    @Override
    public String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeOpenSSLImplementation.getLibraryBuildDate();
        }
        return libraryBuildDate;
    }

    @Override
    public long initialize(boolean isFIPS) throws OpenSSLException {
        // Method name is inherited from the shared NativeInterface contract.
        // The OpenSSL backend initializes its own native library/context here.
        return NativeOpenSSLImplementation.initializeOpenSSL(isFIPS);
    }

    @Override
    public String CTX_getValue(int valueId) throws OpenSSLException {
        return NativeOpenSSLImplementation.CTX_getValue(getOpenSSLContext().getId(), valueId);
    }

    @Override
    public long getByteBufferPointer(ByteBuffer b) {
        return NativeOpenSSLImplementation.getByteBufferPointer(b);
    }

    // =========================================================================
    // Cipher Functions
    // =========================================================================

    @Override
    public long CIPHER_create(String cipher) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipher);
    }

    @Override
    public void CIPHER_init(long cipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_init(getFipsFlag(), cipherId, isEncrypt, paddingId, key, iv);
    }

    @Override
    public int CIPHER_encryptUpdate(long cipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_encryptUpdate(getFipsFlag(), cipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptUpdate(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_decryptUpdate(getFipsFlag(), cipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public int CIPHER_encryptFinal(long cipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_encryptFinal(getFipsFlag(), cipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptFinal(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OpenSSLException {
        return NativeOpenSSLImplementation.CIPHER_decryptFinal(getFipsFlag(), cipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public void CIPHER_delete(long cipherId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
    }

    @Override
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type) throws OpenSSLException {
        // OpenSSL has separate wrap/unwrap methods.
        // type bit 0: 1 = wrap, 0 = unwrap
        // type bit 2: 1 = RFC 5649 padding, 0 = RFC 3394 no padding
        boolean padding = (type & 0x4) != 0;
        boolean wrap = (type & 0x1) != 0;

        if (wrap) {
            return NativeOpenSSLImplementation.KEYWRAP_wrap(getFipsFlag(), key, KEK, padding);
        } else {
            return NativeOpenSSLImplementation.KEYWRAP_unwrap(getFipsFlag(), key, KEK, padding);
        }
    }

    // =========================================================================
    // Methods not yet implemented in OpenSSL - throw UnsupportedOperationException
    // =========================================================================

    @Override
    public void RAND_nextBytes(byte[] buffer) throws OpenSSLException {
        NativeOpenSSLImplementation.RAND_bytes(getFipsFlag(), buffer);
    }

    @Override
    public void RAND_setSeed(byte[] seed) throws OpenSSLException {
        NativeOpenSSLImplementation.RAND_seed(getFipsFlag(), seed);
    }

    @Override
    public void RAND_generateSeed(byte[] seed) throws OpenSSLException {
        // OpenSSL RAND_bytes fills the buffer with cryptographically strong random bytes,
        // which serves as an entropy source for seeding purposes.
        NativeOpenSSLImplementation.RAND_bytes(getFipsFlag(), seed);
    }

    @Override
    public long EXTRAND_create(String algName) throws OpenSSLException {
        return NativeOpenSSLImplementation.EXTRAND_create(getFipsFlag(), algName);
    }

    @Override
    public void EXTRAND_nextBytes(long prngContextId, byte[] buffer) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_nextBytes(getFipsFlag(), prngContextId, buffer);
    }

    @Override
    public void EXTRAND_setSeed(long prngContextId, byte[] seed) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_setSeed(getFipsFlag(), prngContextId, seed);
    }

    @Override
    public void EXTRAND_delete(long prngContextId) throws OpenSSLException {
        NativeOpenSSLImplementation.EXTRAND_delete(getFipsFlag(), prngContextId);
    }

    @Override
    public void CIPHER_clean(long cipherId) throws OpenSSLException {
        throw new UnsupportedOperationException("CIPHER_clean not yet implemented in OpenSSL backend");
    }

    @Override
    public void CIPHER_setPadding(long cipherId, int paddingId) throws OpenSSLException {
        throw new UnsupportedOperationException("CIPHER_setPadding not yet implemented in OpenSSL backend");
    }

    @Override
    public int CIPHER_getBlockSize(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getBlockSize(getFipsFlag(), cipherId);
    }

    @Override
    public int CIPHER_getKeyLength(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getKeyLength(getFipsFlag(), cipherId);
    }

    @Override
    public int CIPHER_getIVLength(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getIVLength(getFipsFlag(), cipherId);
    }

    @Override
    public int CIPHER_getOID(long cipherId) {
        throw new UnsupportedOperationException("CIPHER_getOID not yet implemented in OpenSSL backend");
    }

    @Override
    public long checkHardwareSupport() {
        // OpenSSL handles hardware acceleration internally (e.g., AES-NI on x86)
        // Return 0 to indicate no z/OS-specific hardware support needed
        return 0;
    }

    @Override
    public int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer,
            int inputLength, int mode) {
        throw new UnsupportedOperationException("z_kmc_native not yet implemented in OpenSSL backend");
    }

    /**
     * Maps a JCE digest algorithm name to the canonical OpenSSL EVP_MD_fetch name.
     * OpenSSL 3 requires exact provider-registered names; in particular SHA-3 names
     * must include the hyphen before the bit length (e.g. "SHA3-256", not "SHA3256").
     */
    private String normalizeDigestAlgorithm(String algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Digest algorithm must not be null");
        }

        // Whitelist of approved digest algorithms mapped to OpenSSL canonical names
        switch (algorithm.toUpperCase().replace("-", "").replace("_", "")) {
            case "SHA1":      return "SHA1";
            case "SHA224":    return "SHA-224";
            case "SHA256":    return "SHA-256";
            case "SHA384":    return "SHA-384";
            case "SHA512":    return "SHA-512";
            case "SHA512224": return "SHA-512/224";
            case "SHA512256": return "SHA-512/256";
            case "SHA3224":   return "SHA3-224";
            case "SHA3256":   return "SHA3-256";
            case "SHA3384":   return "SHA3-384";
            case "SHA3512":   return "SHA3-512";
            default:
                throw new IllegalArgumentException("Unsupported or invalid digest algorithm: " + algorithm);
        }
    }

    // ThreadLocal so that concurrent HKDF_create calls on the same adapter instance
    // don't overwrite each other's algorithm before the subsequent extract/expand/derive.
    private final ThreadLocal<String> hkdfDigestAlgorithm = ThreadLocal.withInitial(() -> "SHA-256");

    /**
     * Creates an HKDF context for key derivation operations.
     *
     * Note: OpenSSL's HKDF implementation is stateless, unlike other cryptographic
     * operations that maintain state across multiple calls. Therefore, this method
     * returns a dummy context ID (HKDF_DUMMY_CONTEXT_ID) while storing the digest
     * algorithm in a ThreadLocal. The actual HKDF operations (extract, expand,
     * derive) are performed as single-shot operations using the stored algorithm.
     *
     * @param digestAlgo The digest algorithm to use for HKDF (e.g., "SHA-256")
     * @return A dummy context ID for API compatibility
     * @throws OpenSSLException if the digest algorithm is invalid
     */
    @Override
    public long HKDF_create(String digestAlgo) throws OpenSSLException {
        hkdfDigestAlgorithm.set(normalizeDigestAlgorithm(digestAlgo));
        // OpenSSL HKDF is stateless, return a dummy ID while retaining the algorithm in ThreadLocal.
        return HKDF_DUMMY_CONTEXT_ID;
    }

    @Override
    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_extract(getFipsFlag(), hkdfDigestAlgorithm.get(), saltBytes, inKey);
    }

    @Override
    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes, long prkBytesLen, byte[] info, long infoLen, long okmLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_expand(getFipsFlag(), hkdfDigestAlgorithm.get(), prkBytes, info, (int) okmLen);
    }

    @Override
    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen) throws OpenSSLException {
        return NativeOpenSSLImplementation.HKDF_derive(getFipsFlag(), hkdfDigestAlgorithm.get(), saltBytes, inKey, info, (int) okmLen);
    }

    @Override
    public void HKDF_delete(long hkdfId) throws OpenSSLException {
        // OpenSSL HKDF is stateless - nothing to delete
    }

    @Override
    public int HKDF_size(long hkdfId) throws OpenSSLException {
        throw new UnsupportedOperationException("HKDF_size not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt, int iterations, int keyLength) throws OpenSSLException {
        return NativeOpenSSLImplementation.PBKDF2_derive(getFipsFlag(), hashAlgorithm, password, salt, iterations, keyLength);
    }

    @Override
    public long MLKEY_generate(String cipherName) throws OpenSSLException {
        throw new UnsupportedOperationException("MLKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long MLKEY_createPrivateKey(String cipherName, byte[] privateKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("MLKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long MLKEY_createPublicKey(String cipherName, byte[] publicKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("MLKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] MLKEY_getPrivateKeyBytes(long mlkeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("MLKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] MLKEY_getPublicKeyBytes(long mlkeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("MLKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public void MLKEY_delete(long mlkeyId) {
        throw new UnsupportedOperationException("MLKEY_delete not yet implemented in OpenSSL backend");
    }

    @Override
    public void KEM_encapsulate(long pKeyId, byte[] wrappedKey, byte[] randomKey) throws OpenSSLException {
        throw new UnsupportedOperationException("KEM_encapsulate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] KEM_decapsulate(long pKeyId, byte[] wrappedKey) throws OpenSSLException {
        throw new UnsupportedOperationException("KEM_decapsulate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] PQC_SIGNATURE_sign(long pKeyId, byte[] data) throws OpenSSLException {
        throw new UnsupportedOperationException("PQC_SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean PQC_SIGNATURE_verify(long pKeyId, byte[] sigBytes, byte[] data) throws OpenSSLException {
        throw new UnsupportedOperationException("PQC_SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // POLY1305CIPHER Functions - Not yet implemented
    // =========================================================================

    @Override
    public long POLY1305CIPHER_create(String cipher) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_create not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_init(long cipherId, int isEncrypt, byte[] key, byte[] iv) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_init not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_clean(long cipherId) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_clean not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_setPadding(long cipherId, int paddingId) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_setPadding not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getBlockSize(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getBlockSize not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getKeyLength(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getKeyLength not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getIVLength(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getIVLength not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getOID(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getOID not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_encryptUpdate(long cipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_encryptUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_decryptUpdate(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_decryptUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_encryptFinal(long cipherId, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] tag) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_encryptFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_decryptFinal(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] tag) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_decryptFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_delete(long cipherId) throws OpenSSLException {
        throw new UnsupportedOperationException("POLY1305CIPHER_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // GCM Functions
    // =========================================================================

    @Override
    public long do_GCM_checkHardwareGCMSupport() {
        return -1;
    }

    @Override
    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_encryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_encryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_decryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen,
            int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OpenSSLException {
        throw new UnsupportedOperationException("do_GCM_decryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset,
            int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OpenSSLException {
        // Validate output bounds before calling native code to prevent partial writes
        if (ciphertextOffset < 0 || inLen < 0 || ciphertextOffset + inLen > ciphertext.length) {
            throw new OpenSSLException("GCM encrypt: ciphertext buffer too small or invalid offset");
        }
        if (tagLen < 0 || tagLen > tag.length) {
            throw new OpenSSLException("GCM encrypt: tag buffer too small");
        }
        // Verify the key length matches the cipher bound to this context. A mismatch
        // would cause OpenSSL to silently truncate or reject the key, producing
        // incorrect ciphertext or a confusing native error.
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM encrypt: key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            // Reuse the cached context: GCM_init calls EVP_CIPHER_CTX_reset to clear any prior state.
            NativeOpenSSLImplementation.GCM_init(getFipsFlag(), gcmCtx, 1, key, iv, tagLen);
            byte[] combinedOutput = new byte[inLen + tagLen];
            int totalLen = NativeOpenSSLImplementation.GCM_encryptFinal(getFipsFlag(), gcmCtx,
                    input, inOffset, inLen, combinedOutput, 0, aad, aadLen, tagLen);
            int cipherLen = Math.max(0, totalLen - tagLen);
            System.arraycopy(combinedOutput, 0, ciphertext, ciphertextOffset, cipherLen);
            System.arraycopy(combinedOutput, cipherLen, tag, 0, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid GCM encryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during GCM encryption: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext,
            int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException {
        // Validate input bounds before reading tag from ciphertext to prevent ArrayIndexOutOfBoundsException
        if (cipherOffset < 0 || cipherLen < 0 || tagLen < 0 ||
                cipherOffset + cipherLen + tagLen > ciphertext.length) {
            throw new OpenSSLException("GCM decrypt: ciphertext buffer too small or invalid offset/length");
        }
        // Verify the key length matches the cipher bound to this context.
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM decrypt: key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            byte[] combinedInput = new byte[cipherLen + tagLen];
            System.arraycopy(ciphertext, cipherOffset, combinedInput, 0, cipherLen);
            System.arraycopy(ciphertext, cipherOffset + cipherLen, combinedInput, cipherLen, tagLen);
            // Reuse the cached context: GCM_init calls EVP_CIPHER_CTX_reset to clear any prior state.
            NativeOpenSSLImplementation.GCM_init(getFipsFlag(), gcmCtx, 0, key, iv, tagLen);
            NativeOpenSSLImplementation.GCM_decryptFinal(getFipsFlag(), gcmCtx,
                    combinedInput, 0, combinedInput.length, plaintext, plaintextOffset, aad, aadLen, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid GCM decryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during GCM decryption: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag,
            int tagLen) throws OpenSSLException {
        try {
            int totalLen = NativeOpenSSLImplementation.GCM_encryptFinal(getFipsFlag(), gcmCtx,
                    input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tagLen);
            if (totalLen < 0) {
                return totalLen;  // Return error code
            }
            // totalLen must equal inLen + tagLen exactly; Math.max(0, totalLen - tagLen)
            // would silently read the tag from the wrong position if the native layer
            // returned fewer bytes than expected.
            if (totalLen != inLen + tagLen) {
                throw new OpenSSLException("GCM encrypt final: unexpected output length " + totalLen
                        + " (expected " + (inLen + tagLen) + ")");
            }
            System.arraycopy(ciphertext, ciphertextOffset + inLen, tag, 0, tagLen);

            // Return 0 on success to match OCK behavior
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OpenSSLException {
        try {
            // Note: cipherLen already includes the tag length, so pass it as-is
            // The native code will extract the tag from the end and process the ciphertext
            int result = NativeOpenSSLImplementation.GCM_decryptFinal(getFipsFlag(), gcmCtx,
                    ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, aad, aadLen, tagLen);
            
            if (result < 0) {
                return result;  // Return error code
            }
            // Return 0 on success to match OCK behavior
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException("GCM decrypt final failed: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset) throws OpenSSLException {
        try {
            // For OpenSSL, the context must already be initialized by do_GCM_InitForUpdateEncrypt
            // This method just processes additional data chunks
            int outLen = NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 1,
                    input, inOffset, inLen, ciphertext, ciphertextOffset, null, 0);
            if (outLen < 0) {
                return outLen;  // Return error code
            }
            // Return 0 on success to match OCK behavior
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        try {
            // For OpenSSL, the context must already be initialized by do_GCM_InitForUpdateDecrypt
            // This method just processes additional data chunks
            int outLen = NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 0,
                    ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, null, 0);
            if (outLen < 0) {
                return outLen;  // Return error code
            }
            // Return 0 on success to match OCK behavior
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OpenSSLException {
        // Verify the key length matches the cipher bound to this context.
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM init (update encrypt): key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            // CRITICAL: Always reinitialize the context for each new encryption operation.
            // OpenSSL contexts must be reset between operations to avoid state corruption.
            //
            // NOTE on tagLen: The NativeInterface contract for do_GCM_InitForUpdate* does not
            // carry tagLen. DEFAULT_GCM_TAG_LEN (16) is passed here as a placeholder. This is
            // safe for GCM because the native C code never reads cipherCtx->tagLen back during
            // GCM operations — the actual tag length is always supplied by the caller of
            // GCM_encryptFinal / GCM_decryptFinal and used directly for GET_TAG / SET_TAG.
            NativeOpenSSLImplementation.GCM_init(getFipsFlag(), gcmCtx, 1, key, iv, DEFAULT_GCM_TAG_LEN);
            
            // Process AAD if present
            if (aad != null && aadLen > 0) {
                NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 1,
                        EMPTY_BYTE_ARRAY, 0, 0, EMPTY_BYTE_ARRAY, 0, aad, aadLen);
            }
            
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException("GCM init for update encrypt failed: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OpenSSLException {
        // Verify the key length matches the cipher bound to this context.
        int ctxKeyLen = CIPHER_getKeyLength(gcmCtx);
        if (ctxKeyLen > 0 && keyLen != ctxKeyLen) {
            throw new OpenSSLException("GCM init (update decrypt): key length " + keyLen
                    + " does not match context cipher key length " + ctxKeyLen);
        }
        try {
            // CRITICAL: Always reinitialize the context for each new decryption operation.
            // OpenSSL contexts must be reset between operations to avoid state corruption.
            //
            // NOTE on tagLen: See comment in do_GCM_InitForUpdateEncrypt above.
            NativeOpenSSLImplementation.GCM_init(getFipsFlag(), gcmCtx, 0, key, iv, DEFAULT_GCM_TAG_LEN);
            
            // Process AAD if present
            if (aad != null && aadLen > 0) {
                NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 0,
                        EMPTY_BYTE_ARRAY, 0, 0, EMPTY_BYTE_ARRAY, 0, aad, aadLen);
            }
            
            return 0;
        } catch (Exception e) {
            throw new OpenSSLException("GCM init for update decrypt failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void do_GCM_delete() throws OpenSSLException {
        // No-op for OpenSSL backend - GCM contexts are managed explicitly by create/free.
    }

    @Override
    public void free_GCM_ctx(long gcmContextId) throws OpenSSLException {
        NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), gcmContextId);
    }
    

    @Override
    public long create_GCM_context() throws OpenSSLException {
        // Default to AES-128-GCM for backward compatibility
        return create_GCM_context(16);
    }
    
    @Override
    public long create_GCM_context(int keySize) throws OpenSSLException {
        String cipherName;
        switch (keySize) {
            case 16:  // 128 bits
                cipherName = "AES-128-GCM";
                break;
            case 24:  // 192 bits
                cipherName = "AES-192-GCM";
                break;
            case 32:  // 256 bits
                cipherName = "AES-256-GCM";
                break;
            default:
                throw new OpenSSLException("Unsupported AES key size: " + keySize + " bytes. Supported sizes are 16, 24, and 32 bytes.");
        }
        return NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherName);
    }

    // =========================================================================
    // CCM Functions - Not yet implemented
    // =========================================================================

    @Override
    public long do_CCM_checkHardwareCCMSupport() {
        // OpenSSL handles hardware acceleration internally; return -1 to indicate
        // no z/OS-style hardware CCM support, matching do_GCM_checkHardwareGCMSupport().
        return -1;
    }

    @Override
    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_encryptFastJNI_WithHardwareSupport not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_encryptFastJNI(int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_encryptFastJNI not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_decryptFastJNI_WithHardwareSupport not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_decryptFastJNI(int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OpenSSLException {
        throw new UnsupportedOperationException("do_CCM_decryptFastJNI not yet implemented in OpenSSL backend");
    }

    /**
     * Determines the AES cipher algorithm name based on key length and mode.
     * Consolidates cipher algorithm mapping to avoid code duplication.
     *
     * @param keyLen The AES key length in bytes (16, 24, or 32)
     * @param mode The cipher mode (e.g., "GCM", "CCM")
     * @return The OpenSSL cipher algorithm name (e.g., "AES-128-GCM")
     * @throws IllegalArgumentException if key length is invalid
     */
    private String getAESCipherAlgorithm(int keyLen, String mode) {
        String keySize;
        switch (keyLen) {
            case 16:
                keySize = "128";
                break;
            case 24:
                keySize = "192";
                break;
            case 32:
                keySize = "256";
                break;
            default:
                throw new IllegalArgumentException("Invalid AES key length: " + keyLen + " (must be 16, 24, or 32 bytes)");
        }
        return "AES-" + keySize + "-" + mode;
    }

    @Override
    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input,
            int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) throws OpenSSLException {
        // CCM_encryptFinal writes inLen + tagLen bytes; verify the buffer is large enough.
        if (ciphertext.length < inLen + tagLen) {
            throw new OpenSSLException("CCM encrypt: ciphertext buffer too small (need "
                    + (inLen + tagLen) + " bytes, have " + ciphertext.length + ")");
        }
        String cipherAlg = getAESCipherAlgorithm(keyLen, "CCM");
        long cipherId = NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherAlg);
        try {
            NativeOpenSSLImplementation.CCM_init(getFipsFlag(), cipherId, 1, key, iv, tagLen);
            NativeOpenSSLImplementation.CCM_encryptFinal(
                getFipsFlag(), cipherId, input, 0, inLen, ciphertext, 0, aad, aadLen, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid CCM encryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during CCM encryption: " + e.getMessage(), e);
        } finally {
            NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
        }
    }

    @Override
    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen,
            byte[] ciphertext, int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen)
            throws OpenSSLException {
        String cipherAlg = getAESCipherAlgorithm(keyLen, "CCM");
        long cipherId = NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherAlg);
        try {
            NativeOpenSSLImplementation.CCM_init(getFipsFlag(), cipherId, 0, key, iv, tagLen);
            NativeOpenSSLImplementation.CCM_decryptFinal(
                getFipsFlag(), cipherId, ciphertext, 0, ciphertextLength, plaintext, 0, aad, aadLen, tagLen);
            return 0;
        } catch (IllegalArgumentException e) {
            throw new OpenSSLException("Invalid CCM decryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OpenSSLException("Unexpected error during CCM decryption: " + e.getMessage(), e);
        } finally {
            NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
        }
    }

    @Override
    public void do_CCM_delete() throws OpenSSLException {
        // No-op for OpenSSL backend - contexts are managed per-operation
    }

    // =========================================================================
    // RSA Cipher Functions - Not yet implemented
    // =========================================================================

    @Override
    public int RSACIPHER_public_encrypt(long rsaKeyId, int rsaPaddingId, int mdId, int mgf1Id, byte[] plaintext,
            int plaintextOffset, int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("RSACIPHER_public_encrypt not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSACIPHER_private_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OpenSSLException {
        throw new UnsupportedOperationException("RSACIPHER_private_encrypt not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSACIPHER_public_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset) throws OpenSSLException {
        throw new UnsupportedOperationException("RSACIPHER_public_decrypt not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSACIPHER_private_decrypt(long rsaKeyId, int rsaPaddingId, int mdId, int mgf1Id, byte[] ciphertext,
            int ciphertextOffset, int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey)
            throws OpenSSLException {
        throw new UnsupportedOperationException("RSACIPHER_private_decrypt not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // DH Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long DHKEY_generate(int numBits) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_generateParameters(int numBits) {
        throw new UnsupportedOperationException("DHKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_generate(byte[] dhParameters) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_getParameters(long dhKeyId) {
        throw new UnsupportedOperationException("DHKEY_getParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_createPKey(long dhKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_createPKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_computeDHSecret(long pubKeyId, long privKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_computeDHSecret not yet implemented in OpenSSL backend");
    }

    @Override
    public void DHKEY_delete(long dhKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DHKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // RSA Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long RSAKEY_generate(int numBits, long e) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long RSAKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSAKEY_size(long rsaKeyId) {
        throw new UnsupportedOperationException("RSAKEY_size not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAKEY_delete(long rsaKeyId) {
        throw new UnsupportedOperationException("RSAKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // DSA Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long DSAKEY_generate(int numBits) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_generateParameters(int numBits) {
        throw new UnsupportedOperationException("DSAKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_generate(byte[] dsaParameters) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_getParameters(long dsaKeyId) {
        throw new UnsupportedOperationException("DSAKEY_getParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_createPKey(long dsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_createPKey not yet implemented in OpenSSL backend");
    }

    @Override
    public void DSAKEY_delete(long dsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DSAKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // PKey Functions - Not yet implemented
    // =========================================================================

    @Override
    public void PKEY_delete(long pkeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("PKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // Digest Functions
    // =========================================================================

    @Override
    public long DIGEST_create(String digestAlgo) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_create(getFipsFlag(), normalizeDigestAlgorithm(digestAlgo));
    }

    @Override
    public long DIGEST_copy(long digestId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_copy(getFipsFlag(), digestId);
    }

    @Override
    public int DIGEST_update(long digestId, byte[] input, int offset, int length) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_update(getFipsFlag(), digestId, input, offset, length);
    }

    @Override
    public void DIGEST_updateFastJNI(long digestId, long inputBuffer, int length) throws OpenSSLException {
        throw new UnsupportedOperationException("DIGEST_updateFastJNI not supported by OpenSSL backend");
    }

    @Override
    public byte[] DIGEST_digest(long digestId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_digest(getFipsFlag(), digestId);
    }

    @Override
    public void DIGEST_digest_and_reset(long digestId, long outputBuffer, int length) throws OpenSSLException {
        throw new UnsupportedOperationException("DIGEST_digest_and_reset(long, long, int) not supported by OpenSSL backend");
    }

    @Override
    public int DIGEST_digest_and_reset(long digestId, byte[] output) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_digest_and_reset(getFipsFlag(), digestId, output);
    }

    @Override
    public int DIGEST_size(long digestId) throws OpenSSLException {
        return NativeOpenSSLImplementation.DIGEST_size(getFipsFlag(), digestId);
    }

    @Override
    public void DIGEST_reset(long digestId) throws OpenSSLException {
        NativeOpenSSLImplementation.DIGEST_reset(getFipsFlag(), digestId);
    }

    @Override
    public void DIGEST_delete(long digestId) throws OpenSSLException {
        NativeOpenSSLImplementation.DIGEST_delete(getFipsFlag(), digestId);
    }

    @Override
    public int DIGEST_PKCS12KeyDeriveHelp(long digestId, byte[] input, int offset, int length, int iterationCount)
            throws OpenSSLException {
        throw new UnsupportedOperationException("DIGEST_PKCS12KeyDeriveHelp not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public byte[] SIGNATURE_sign(long digestId, long pkeyId, boolean convert) throws OpenSSLException {
        throw new UnsupportedOperationException("SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean SIGNATURE_verify(long digestId, long pkeyId, byte[] sigBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId, byte[] bytes) throws OpenSSLException {
        throw new UnsupportedOperationException("SIGNATUREEdDSA_signOneShot not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId, byte[] sigBytes, byte[] oneShot) throws OpenSSLException {
        throw new UnsupportedOperationException("SIGNATUREEdDSA_verifyOneShot not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // RSA PSS Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public int RSAPSS_signInit(long rsaPssId, long pkeyId, int saltlen, boolean convert) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_signInit not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId, int saltlen) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_verifyInit not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSAPSS_getSigLen(long rsaPssId) {
        throw new UnsupportedOperationException("RSAPSS_getSigLen not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_signFinal(long rsaPssId, byte[] signature, int length) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_signFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean RSAPSS_verifyFinal(long rsaPssId, byte[] sigBytes, int length) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_verifyFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public long RSAPSS_createContext(String digestAlgo, String mgf1SpecAlgo) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_createContext not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_releaseContext(long rsaPssId) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_releaseContext not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input, int offset, int length) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_digestUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_reset(long digestId) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_reset not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_resetDigest(long rsaPssId) throws OpenSSLException {
        throw new UnsupportedOperationException("RSAPSS_resetDigest not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // DSA Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public byte[] DSANONE_SIGNATURE_sign(byte[] digest, long dsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("DSANONE_SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean DSANONE_SIGNATURE_verify(byte[] digest, long dsaKeyId, byte[] sigBytes) throws OpenSSLException {
        throw new UnsupportedOperationException("DSANONE_SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // RSASSL Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public byte[] RSASSL_SIGNATURE_sign(byte[] digest, long rsaKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("RSASSL_SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean RSASSL_SIGNATURE_verify(byte[] digest, long rsaKeyId, byte[] sigBytes, boolean convert)
            throws OpenSSLException {
        throw new UnsupportedOperationException("RSASSL_SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // HMAC Functions
    // =========================================================================

    @Override
    public long HMAC_create(String digestAlgo) throws OpenSSLException {
        return NativeOpenSSLImplementation.HMAC_create(getFipsFlag(), normalizeDigestAlgorithm(digestAlgo));
    }

    @Override
    public int HMAC_update(long hmacId, byte[] key, int keyLength, byte[] input, int inputOffset, int inputLength,
            boolean needInit) throws OpenSSLException {
        if (needInit) {
            NativeOpenSSLImplementation.HMAC_init(getFipsFlag(), hmacId, key, keyLength);
        }
        return NativeOpenSSLImplementation.HMAC_update(getFipsFlag(), hmacId, input, inputOffset, inputLength);
    }

    @Override
    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength, byte[] hmac, boolean needInit)
            throws OpenSSLException {
        if (needInit) {
            NativeOpenSSLImplementation.HMAC_init(getFipsFlag(), hmacId, key, keyLength);
        }
        return NativeOpenSSLImplementation.HMAC_doFinal(getFipsFlag(), hmacId, hmac, 0);
    }

    @Override
    public int HMAC_size(long hmacId) throws OpenSSLException {
        return NativeOpenSSLImplementation.HMAC_size(getFipsFlag(), hmacId);
    }

    @Override
    public void HMAC_delete(long hmacId) throws OpenSSLException {
        NativeOpenSSLImplementation.HMAC_delete(getFipsFlag(), hmacId);
    }

    // =========================================================================
    // EC Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long ECKEY_generate(int numBits) throws OpenSSLException {
        throw new UnsupportedOperationException("ECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_generate(String curveOid) throws OpenSSLException {
        throw new UnsupportedOperationException("ECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long XECKEY_generate(int option, long bufferPtr) throws OpenSSLException {
        throw new UnsupportedOperationException("XECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_generateParameters(int numBits) throws OpenSSLException {
        throw new UnsupportedOperationException("ECKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_generateParameters(String curveOid) throws OpenSSLException {
        throw new UnsupportedOperationException("ECKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_generate(byte[] ecParameters) throws OpenSSLException {
        throw new UnsupportedOperationException("ECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_createPrivateKey(byte[] privateKeyBytes) throws OpenSSLException {
        if (privateKeyBytes == null || privateKeyBytes.length == 0) {
            throw new OpenSSLException("Private key bytes cannot be null or empty");
        }
        // Store the key bytes and return a unique ID
        long keyId = ecKeyIdCounter.getAndIncrement();
        ecKeyStore.put(keyId, privateKeyBytes.clone());
        return keyId;
    }

    @Override
    public long XECKEY_createPrivateKey(byte[] privateKeyBytes, long bufferPtr) throws OpenSSLException {
        // For OpenSSL, we don't use bufferPtr, just store the key bytes
        return ECKEY_createPrivateKey(privateKeyBytes);
    }

    @Override
    public long ECKEY_createPublicKey(byte[] publicKeyBytes, byte[] parameterBytes) throws OpenSSLException {
        if (publicKeyBytes == null || publicKeyBytes.length == 0) {
            throw new OpenSSLException("Public key bytes cannot be null or empty");
        }
        // Store the key bytes and return a unique ID
        // Note: parameterBytes are embedded in X.509 format, so we don't need them separately
        long keyId = ecKeyIdCounter.getAndIncrement();
        ecKeyStore.put(keyId, publicKeyBytes.clone());
        return keyId;
    }

    @Override
    public long XECKEY_createPublicKey(byte[] publicKeyBytes) throws OpenSSLException {
        return ECKEY_createPublicKey(publicKeyBytes, null);
    }

    @Override
    public byte[] ECKEY_getParameters(long ecKeyId) {
        // Parameters are embedded in the X.509 public key format
        // For now, return null as this is typically not needed
        return null;
    }

    @Override
    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId) throws OpenSSLException {
        byte[] keyBytes = ecKeyStore.get(ecKeyId);
        if (keyBytes == null) {
            throw new OpenSSLException("Invalid EC key ID: " + ecKeyId);
        }
        return keyBytes.clone();
    }

    @Override
    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId) throws OpenSSLException {
        return ECKEY_getPrivateKeyBytes(xecKeyId);
    }

    @Override
    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId) throws OpenSSLException {
        byte[] keyBytes = ecKeyStore.get(ecKeyId);
        if (keyBytes == null) {
            throw new OpenSSLException("Invalid EC key ID: " + ecKeyId);
        }
        return keyBytes.clone();
    }

    @Override
    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId) throws OpenSSLException {
        return ECKEY_getPublicKeyBytes(xecKeyId);
    }

    @Override
    public long ECKEY_createPKey(long ecKeyId) throws OpenSSLException {
        // For OpenSSL, we don't need a separate PKey - the key ID is sufficient
        return ecKeyId;
    }

    @Override
    public void ECKEY_delete(long ecKeyId) throws OpenSSLException {
        ecKeyStore.remove(ecKeyId);
    }

    @Override
    public void XECKEY_delete(long xecKeyId) throws OpenSSLException {
        ECKEY_delete(xecKeyId);
    }

    @Override
    public long XDHKeyAgreement_init(long privId) {
        throw new UnsupportedOperationException("XDHKeyAgreement_init not yet implemented in OpenSSL backend");
    }

    @Override
    public void XDHKeyAgreement_setPeer(long genCtx, long pubId) {
        throw new UnsupportedOperationException("XDHKeyAgreement_setPeer not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId, long privEcKeyId) throws OpenSSLException {
        throw new UnsupportedOperationException("ECKEY_computeECDHSecret not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] XECKEY_computeECDHSecret(long genCtx, long pubEcKeyId, long privEcKeyId, int secrectBufferSize)
            throws OpenSSLException {
        throw new UnsupportedOperationException("XECKEY_computeECDHSecret not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes, int digestBytesLen, long ecPrivateKeyId)
            throws OpenSSLException {
        // Get the private key bytes from storage
        byte[] privateKeyBytes = ecKeyStore.get(ecPrivateKeyId);
        if (privateKeyBytes == null) {
            throw new OpenSSLException("Invalid EC private key ID: " + ecPrivateKeyId);
        }
        
        try {
            // Create signature context with the EC private key
            // Use "NONEwithECDSA" since we already have a pre-computed digest
            long signatureId = NativeOpenSSLImplementation.SIGNATURE_create(
                getFipsFlag(),
                privateKeyBytes,
                privateKeyBytes.length,
                "NONEwithECDSA",
                0  // MODE_SIGN
            );
            
            try {
                // Update with the pre-computed digest
                int updateResult = NativeOpenSSLImplementation.SIGNATURE_update(
                    getFipsFlag(),
                    signatureId,
                    digestBytes,
                    0,
                    digestBytesLen
                );
                
                if (updateResult != 1) {
                    throw new OpenSSLException("Failed to update ECDSA signature with digest");
                }
                
                // Sign and get signature bytes
                byte[] signature = NativeOpenSSLImplementation.SIGNATURE_sign(getFipsFlag(), signatureId);
                if (signature == null) {
                    throw new OpenSSLException("ECDSA signature operation returned null");
                }
                
                return signature;
            } finally {
                // Clean up signature context
                NativeOpenSSLImplementation.SIGNATURE_delete(getFipsFlag(), signatureId);
            }
        } catch (Exception e) {
            throw new OpenSSLException("ECDSA signature failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes, int digestBytesLen, byte[] sigBytes, int sigBytesLen,
            long ecPublicKeyId) throws OpenSSLException {
        // Get the public key bytes from storage
        byte[] publicKeyBytes = ecKeyStore.get(ecPublicKeyId);
        if (publicKeyBytes == null) {
            throw new OpenSSLException("Invalid EC public key ID: " + ecPublicKeyId);
        }
        
        try {
            // Create signature context with the EC public key
            // Use "NONEwithECDSA" since we already have a pre-computed digest
            long signatureId = NativeOpenSSLImplementation.SIGNATURE_create(
                getFipsFlag(),
                publicKeyBytes,
                publicKeyBytes.length,
                "NONEwithECDSA",
                1  // MODE_VERIFY
            );
            
            try {
                // Update with the pre-computed digest
                int updateResult = NativeOpenSSLImplementation.SIGNATURE_update(
                    getFipsFlag(),
                    signatureId,
                    digestBytes,
                    0,
                    digestBytesLen
                );
                
                if (updateResult != 1) {
                    throw new OpenSSLException("Failed to update ECDSA verification with digest");
                }
                
                // Verify signature
                int verifyResult = NativeOpenSSLImplementation.SIGNATURE_verify(
                    getFipsFlag(),
                    signatureId,
                    sigBytes
                );
                
                // Return true if valid (1), false if invalid (0), throw on error (negative)
                if (verifyResult < 0) {
                    throw new OpenSSLException("ECDSA verification operation failed");
                }
                
                return verifyResult == 1;
            } finally {
                // Clean up signature context
                NativeOpenSSLImplementation.SIGNATURE_delete(getFipsFlag(), signatureId);
            }
        } catch (Exception e) {
            throw new OpenSSLException("ECDSA verification failed: " + e.getMessage(), e);
        }
    }

    // Note: Additional methods from NativeInterface that are not yet implemented
    // will throw UnsupportedOperationException. These can be added as needed.
}


