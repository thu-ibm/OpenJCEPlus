/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.HMAC;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import com.ibm.crypto.plus.provider.openssl.OpenSSLHMAC;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Wrapper class that uses OpenSSL HMAC when available, with fallback to OCK.
 * This follows the same pattern as OpenSSLMessageDigestWrapper for OpenSSL integration.
 */
abstract class OpenSSLHMACWrapper extends MacSpi {

    private OpenJCEPlusProvider provider = null;
    private HMAC ockHmac = null;
    private OpenSSLHMAC opensslHmac = null;
    private boolean useOpenSSL = false;
    private String algorithm;

    OpenSSLHMACWrapper(OpenJCEPlusProvider provider, String algorithm) {
        this.provider = provider;
        this.algorithm = algorithm;
        
        // Try to use OpenSSL if available
        OpenSSLContext opensslContext = provider.getOpenSSLContext();
        useOpenSSL = (opensslContext != null);

        if (useOpenSSL) {
            try {
                opensslHmac = createOpenSSLHMAC(opensslContext, algorithm);
            } catch (OpenSSLException e) {
                // Fall back to OCK if OpenSSL fails
                useOpenSSL = false;
            }
        }

        // Fall back to OCK if OpenSSL is not available or failed
        if (!useOpenSSL) {
            try {
                ockHmac = HMAC.getInstance(provider.getOCKContext(), algorithm);
            } catch (Exception e) {
                throw provider.providerException("Failure in HMAC", e);
            }
        }
    }

    /**
     * Create OpenSSL HMAC instance based on algorithm name
     */
    private OpenSSLHMAC createOpenSSLHMAC(OpenSSLContext opensslContext, String algorithm) 
            throws OpenSSLException {
        switch (algorithm) {
            case "HmacMD5":
                return OpenSSLHMAC.getInstanceHmacMD5(opensslContext);
            case "HmacSHA1":
                return OpenSSLHMAC.getInstanceHmacSHA1(opensslContext);
            case "HmacSHA224":
                return OpenSSLHMAC.getInstanceHmacSHA224(opensslContext);
            case "HmacSHA256":
                return OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
            case "HmacSHA384":
                return OpenSSLHMAC.getInstanceHmacSHA384(opensslContext);
            case "HmacSHA512":
                return OpenSSLHMAC.getInstanceHmacSHA512(opensslContext);
            case "HmacSHA3-224":
                return OpenSSLHMAC.getInstanceHmacSHA3_224(opensslContext);
            case "HmacSHA3-256":
                return OpenSSLHMAC.getInstanceHmacSHA3_256(opensslContext);
            case "HmacSHA3-384":
                return OpenSSLHMAC.getInstanceHmacSHA3_384(opensslContext);
            case "HmacSHA3-512":
                return OpenSSLHMAC.getInstanceHmacSHA3_512(opensslContext);
            default:
                throw new OpenSSLException("Unsupported algorithm: " + algorithm);
        }
    }

    @Override
    protected int engineGetMacLength() {
        try {
            if (useOpenSSL) {
                return opensslHmac.engineGetMacLength();
            } else {
                return ockHmac.getMacLength();
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineGetMacLength", e);
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key is null");
        }
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey");
        }

        try {
            if (useOpenSSL) {
                opensslHmac.engineInit(key, params);
            } else {
                ockHmac.initialize(key.getEncoded());
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw e;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInit", e);
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
                opensslHmac.engineUpdate(input, offset, length);
            } else {
                ockHmac.update(input, offset, length);
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        try {
            if (useOpenSSL) {
                return opensslHmac.engineDoFinal();
            } else {
                return ockHmac.doFinal();
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected void engineReset() {
        try {
            if (useOpenSSL) {
                opensslHmac.engineReset();
            } else {
                ockHmac.reset();
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineReset", e);
        }
    }

    // Concrete implementations for each algorithm
    public static final class HmacMD5 extends OpenSSLHMACWrapper {
        public HmacMD5(OpenJCEPlusProvider provider) {
            super(provider, "HmacMD5");
        }
    }

    public static final class HmacSHA1 extends OpenSSLHMACWrapper {
        public HmacSHA1(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA1");
        }
    }

    public static final class HmacSHA224 extends OpenSSLHMACWrapper {
        public HmacSHA224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA224");
        }
    }

    public static final class HmacSHA256 extends OpenSSLHMACWrapper {
        public HmacSHA256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA256");
        }
    }

    public static final class HmacSHA384 extends OpenSSLHMACWrapper {
        public HmacSHA384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA384");
        }
    }

    public static final class HmacSHA512 extends OpenSSLHMACWrapper {
        public HmacSHA512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512");
        }
    }

    public static final class HmacSHA3_224 extends OpenSSLHMACWrapper {
        public HmacSHA3_224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-224");
        }
    }

    public static final class HmacSHA3_256 extends OpenSSLHMACWrapper {
        public HmacSHA3_256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-256");
        }
    }

    public static final class HmacSHA3_384 extends OpenSSLHMACWrapper {
        public HmacSHA3_384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-384");
        }
    }

    public static final class HmacSHA3_512 extends OpenSSLHMACWrapper {
        public HmacSHA3_512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-512");
        }
    }
}


