/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import com.ibm.crypto.plus.provider.openssl.OpenSSLHKDF;
import ibm.jceplus.junit.base.BaseTestJunit5;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for OpenSSL HKDF implementation based on RFC 5869.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLHKDF extends BaseTestJunit5 {

    private OpenJCEPlusProvider provider;
    private OpenSSLContext opensslContext;

    @BeforeAll
    public void beforeAll() throws Exception {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        provider = (OpenJCEPlusProvider) java.security.Security.getProvider(getProviderName());
        opensslContext = provider.getOpenSSLContext();
    }

    /**
     * RFC 5869 Test Case 1 - Basic test with SHA-256.
     */
    @Test
    public void testHKDF_RFC5869_Case1() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(opensslContext, "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 42;

        byte[] okm = hkdf.derive(salt, ikm, info, length);

        String expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assertEquals(expected, bytesToHex(okm));
    }

    /**
     * RFC 5869 Test Case 3 - Test with zero-length salt and info.
     */
    @Test
    public void testHKDF_RFC5869_Case3() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = null;
        byte[] info = null;
        int length = 42;

        byte[] okm = hkdf.derive(salt, ikm, info, length);

        String expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
        assertEquals(expected, bytesToHex(okm));
    }

    /**
     * Test HKDF extract phase separately.
     */
    @Test
    public void testHKDF_Extract() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");

        byte[] prk = hkdf.extract(salt, ikm);

        String expected = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        assertEquals(expected, bytesToHex(prk));
        assertEquals(32, prk.length); // SHA-256 output
    }

    /**
     * Test HKDF expand phase separately.
     */
    @Test
    public void testHKDF_Expand() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] prk = hexToBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 42;

        byte[] okm = hkdf.expand(prk, info, length);

        String expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assertEquals(expected, bytesToHex(okm));
    }

    /**
     * Test two-phase HKDF (extract then expand).
     */
    @Test
    public void testHKDF_TwoPhase() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 42;

        // Extract
        byte[] prk = hkdf.extract(salt, ikm);
        // Expand
        byte[] okm = hkdf.expand(prk, info, length);

        String expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assertEquals(expected, bytesToHex(okm));
    }

    /**
     * Test HKDF with SHA-384.
     */
    @Test
    public void testHKDF_SHA384() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA384");

        byte[] ikm = new byte[32];
        Arrays.fill(ikm, (byte) 0x42);
        byte[] salt = "test salt".getBytes();
        byte[] info = "test info".getBytes();
        int length = 48;

        byte[] okm = hkdf.derive(salt, ikm, info, length);

        assertNotNull(okm);
        assertEquals(48, okm.length);
    }

    /**
     * Test HKDF with SHA-512.
     */
    @Test
    public void testHKDF_SHA512() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA512");

        byte[] ikm = new byte[64];
        Arrays.fill(ikm, (byte) 0x55);
        byte[] salt = "another salt".getBytes();
        byte[] info = "another info".getBytes();
        int length = 64;

        byte[] okm = hkdf.derive(salt, ikm, info, length);

        assertNotNull(okm);
        assertEquals(64, okm.length);
    }

    /**
     * Test deriveKey method that returns SecretKey.
     */
    @Test
    public void testHKDF_DeriveKey() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 32;

        SecretKey key = hkdf.deriveKey(salt, ikm, info, length, "AES");

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    /**
     * Test deriveKeyTwoPhase method.
     */
    @Test
    public void testHKDF_DeriveKeyTwoPhase() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 32;

        SecretKey key = hkdf.deriveKeyTwoPhase(salt, ikm, info, length, "AES");

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    /**
     * Test HKDF with null IKM - should throw exception.
     */
    @Test
    public void testHKDF_NullIKM() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        assertThrows(InvalidKeyException.class, () -> {
            hkdf.derive(null, null, null, 32);
        });
    }

    /**
     * Test HKDF with invalid length - should throw exception.
     */
    @Test
    public void testHKDF_InvalidLength() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = new byte[32];
        
        assertThrows(InvalidKeyException.class, () -> {
            hkdf.derive(null, ikm, null, 0);
        });
    }

    /**
     * Test HKDF consistency - same inputs produce same output.
     */
    @Test
    public void testHKDF_Consistency() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 42;

        byte[] okm1 = hkdf.derive(salt, ikm, info, length);
        byte[] okm2 = hkdf.derive(salt, ikm, info, length);

        assertArrayEquals(okm1, okm2);
    }

    /**
     * Test HKDF with different salts produces different output.
     */
    @Test
    public void testHKDF_DifferentSalts() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt1 = hexToBytes("000102030405060708090a0b0c");
        byte[] salt2 = hexToBytes("0f0e0d0c0b0a09080706050403");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int length = 42;

        byte[] okm1 = hkdf.derive(salt1, ikm, info, length);
        byte[] okm2 = hkdf.derive(salt2, ikm, info, length);

        assertFalse(Arrays.equals(okm1, okm2));
    }

    /**
     * Test HKDF with different info produces different output.
     */
    @Test
    public void testHKDF_DifferentInfo() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info1 = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        byte[] info2 = hexToBytes("a0a1a2a3a4a5a6a7a8a9");
        int length = 42;

        byte[] okm1 = hkdf.derive(salt, ikm, info1, length);
        byte[] okm2 = hkdf.derive(salt, ikm, info2, length);

        assertFalse(Arrays.equals(okm1, okm2));
    }

    /**
     * Test getDigestAlgorithm method.
     */
    @Test
    public void testGetDigestAlgorithm() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");
        assertEquals("SHA256", hkdf.getDigestAlgorithm());
    }

    /**
     * Test isFIPS method.
     */
    @Test
    public void testIsFIPS() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");
        assertEquals(provider.isFIPS(), hkdf.isFIPS());
    }

    /**
     * Test getMaxOutputLength method.
     */
    @Test
    public void testGetMaxOutputLength() throws Exception {
        OpenSSLHKDF hkdf256 = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");
        assertEquals(255 * 32, hkdf256.getMaxOutputLength());

        OpenSSLHKDF hkdf384 = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA384");
        assertEquals(255 * 48, hkdf384.getMaxOutputLength());

        OpenSSLHKDF hkdf512 = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA512");
        assertEquals(255 * 64, hkdf512.getMaxOutputLength());
    }

    /**
     * Test HKDF with maximum output length.
     */
    @Test
    public void testHKDF_MaxOutputLength() throws Exception {
        OpenSSLHKDF hkdf = new OpenSSLHKDF(provider.getOpenSSLContext(), "SHA256");

        byte[] ikm = new byte[32];
        Arrays.fill(ikm, (byte) 0x42);
        byte[] salt = "salt".getBytes();
        byte[] info = "info".getBytes();
        int maxLength = hkdf.getMaxOutputLength();

        byte[] okm = hkdf.derive(salt, ikm, info, maxLength);

        assertNotNull(okm);
        assertEquals(maxLength, okm.length);
    }

    /**
     * Helper method to convert hex string to bytes.
     */
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Helper method to convert bytes to hex string.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}


