/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.Digest;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import com.ibm.crypto.plus.provider.openssl.OpenSSLMessageDigest;
import java.security.MessageDigestSpi;

/**
 * Wrapper class that uses OpenSSL digest when available, with fallback to OCK.
 * This follows the same pattern as AESCipher for OpenSSL integration.
 */
abstract class OpenSSLMessageDigestWrapper extends MessageDigestSpi implements Cloneable {

    private OpenJCEPlusProvider provider = null;
    private Digest ockDigest = null;
    private OpenSSLMessageDigest opensslDigest = null;
    private boolean useOpenSSL = false;
    private String algorithm;

    OpenSSLMessageDigestWrapper(OpenJCEPlusProvider provider, String algorithm) {
        this.provider = provider;
        this.algorithm = algorithm;
        
        // Try to use OpenSSL if available
        OpenSSLContext opensslContext = provider.getOpenSSLContext();
        useOpenSSL = (opensslContext != null);

        if (useOpenSSL) {
            try {
                opensslDigest = createOpenSSLDigest(opensslContext, algorithm);
            } catch (OpenSSLException e) {
                // Fall back to OCK if OpenSSL fails
                useOpenSSL = false;
            }
        }

        // Fall back to OCK if OpenSSL is not available or failed
        if (!useOpenSSL) {
            try {
                ockDigest = Digest.getInstance(provider.getOCKContext(), algorithm, provider);
            } catch (Exception e) {
                throw provider.providerException("Failure in MessageDigest", e);
            }
        }
    }

    /**
     * Create OpenSSL digest instance based on algorithm name
     */
    private OpenSSLMessageDigest createOpenSSLDigest(OpenSSLContext opensslContext, String algorithm) 
            throws OpenSSLException {
        switch (algorithm) {
            case "MD5":
                return OpenSSLMessageDigest.getInstanceMD5(opensslContext);
            case "SHA1":
            case "SHA-1":
                return OpenSSLMessageDigest.getInstanceSHA1(opensslContext);
            case "SHA224":
            case "SHA-224":
                return OpenSSLMessageDigest.getInstanceSHA224(opensslContext);
            case "SHA256":
            case "SHA-256":
                return OpenSSLMessageDigest.getInstanceSHA256(opensslContext);
            case "SHA384":
            case "SHA-384":
                return OpenSSLMessageDigest.getInstanceSHA384(opensslContext);
            case "SHA512":
            case "SHA-512":
                return OpenSSLMessageDigest.getInstanceSHA512(opensslContext);
            case "SHA512-224":
            case "SHA-512/224":
                return OpenSSLMessageDigest.getInstanceSHA512_224(opensslContext);
            case "SHA512-256":
            case "SHA-512/256":
                return OpenSSLMessageDigest.getInstanceSHA512_256(opensslContext);
            case "SHA3-224":
                return OpenSSLMessageDigest.getInstanceSHA3_224(opensslContext);
            case "SHA3-256":
                return OpenSSLMessageDigest.getInstanceSHA3_256(opensslContext);
            case "SHA3-384":
                return OpenSSLMessageDigest.getInstanceSHA3_384(opensslContext);
            case "SHA3-512":
                return OpenSSLMessageDigest.getInstanceSHA3_512(opensslContext);
            default:
                throw new OpenSSLException("Unsupported algorithm: " + algorithm);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] singleByte = new byte[1];
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        if (input == null) {
            throw new IllegalArgumentException("No input buffer given");
        }
        if ((offset < 0) || (length < 0) || (offset > input.length - length)) {
            throw new ArrayIndexOutOfBoundsException("Range out of bounds for buffer of length " 
                    + input.length + " using offset: " + offset + ", input length: " + length);
        }
        
        try {
            if (useOpenSSL) {
                opensslDigest.engineUpdate(input, offset, length);
            } else {
                ockDigest.update(input, offset, length);
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected byte[] engineDigest() {
        try {
            if (useOpenSSL) {
                return opensslDigest.engineDigest();
            } else {
                return ockDigest.digest();
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDigest", e);
        }
    }

    @Override
    protected int engineGetDigestLength() {
        try {
            if (useOpenSSL) {
                return opensslDigest.engineGetDigestLength();
            } else {
                return ockDigest.getDigestLength();
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineGetDigestLength", e);
        }
    }

    @Override
    protected void engineReset() {
        try {
            if (useOpenSSL) {
                opensslDigest.engineReset();
            } else {
                ockDigest.reset();
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineReset", e);
        }
    }

    @Override
    synchronized public Object clone() throws CloneNotSupportedException {
        OpenSSLMessageDigestWrapper copy = (OpenSSLMessageDigestWrapper) super.clone();
        
        try {
            if (useOpenSSL) {
                copy.opensslDigest = (OpenSSLMessageDigest) opensslDigest.clone();
            } else {
                copy.ockDigest = (Digest) ockDigest.clone();
            }
        } catch (Exception e) {
            throw new CloneNotSupportedException("Failed to clone digest: " + e.getMessage());
        }
        
        return copy;
    }

    // Inner classes for each algorithm
    public static final class MD5 extends OpenSSLMessageDigestWrapper {
        public MD5(OpenJCEPlusProvider provider) {
            super(provider, "MD5");
        }
    }

    public static final class SHA1 extends OpenSSLMessageDigestWrapper {
        public SHA1(OpenJCEPlusProvider provider) {
            super(provider, "SHA1");
        }
    }

    public static final class SHA224 extends OpenSSLMessageDigestWrapper {
        public SHA224(OpenJCEPlusProvider provider) {
            super(provider, "SHA224");
        }
    }

    public static final class SHA256 extends OpenSSLMessageDigestWrapper {
        public SHA256(OpenJCEPlusProvider provider) {
            super(provider, "SHA256");
        }
    }

    public static final class SHA384 extends OpenSSLMessageDigestWrapper {
        public SHA384(OpenJCEPlusProvider provider) {
            super(provider, "SHA384");
        }
    }

    public static final class SHA512 extends OpenSSLMessageDigestWrapper {
        public SHA512(OpenJCEPlusProvider provider) {
            super(provider, "SHA512");
        }
    }

    public static final class SHA512_224 extends OpenSSLMessageDigestWrapper {
        public SHA512_224(OpenJCEPlusProvider provider) {
            super(provider, "SHA512-224");
        }
    }

    public static final class SHA512_256 extends OpenSSLMessageDigestWrapper {
        public SHA512_256(OpenJCEPlusProvider provider) {
            super(provider, "SHA512-256");
        }
    }

    public static final class SHA3_224 extends OpenSSLMessageDigestWrapper {
        public SHA3_224(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-224");
        }
    }

    public static final class SHA3_256 extends OpenSSLMessageDigestWrapper {
        public SHA3_256(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-256");
        }
    }

    public static final class SHA3_384 extends OpenSSLMessageDigestWrapper {
        public SHA3_384(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-384");
        }
    }

    public static final class SHA3_512 extends OpenSSLMessageDigestWrapper {
        public SHA3_512(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-512");
        }
    }
}


