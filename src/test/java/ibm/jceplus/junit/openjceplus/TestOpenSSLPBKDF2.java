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
import com.ibm.crypto.plus.provider.openssl.OpenSSLPBKDF2;
import ibm.jceplus.junit.base.BaseTestJunit5;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for OpenSSL PBKDF2 implementation.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLPBKDF2 extends BaseTestJunit5 {

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
     * Test PBKDF2 with HmacSHA256 using RFC 7914 test vector.
     */
    @Test
    public void testPBKDF2_HmacSHA256_RFC7914() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(opensslContext, "HmacSHA256");

        // RFC 7914 Test Vector 1
        char[] password = "passwd".toCharArray();
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1;
        int keyLength = 512; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        String expected = "55ac046e56e3089fec1691c22544b605" +
                "f94185216dde0465e68b9d57c20dacbc" +
                "49ca9cccf179b645991664b39d77ef31" +
                "7c71b845b1e30bd509112041d3a19783";

        String actual = bytesToHex(key.getEncoded());
        assertEquals(expected, actual, "RFC 7914 test vector 1 failed");
    }

    /**
     * Test PBKDF2 with HmacSHA256 using RFC 7914 test vector with high iteration count.
     */
    @Test
    public void testPBKDF2_HmacSHA256_RFC7914_HighIterations() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(opensslContext, "HmacSHA256");

        // RFC 7914 Test Vector 2
        char[] password = "Password".toCharArray();
        byte[] salt = "NaCl".getBytes("ASCII");
        int iterations = 80000;
        int keyLength = 512; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        String expected = "4ddcd8f60b98be21830cee5ef22701f9" +
                "641a4418d04c0414aeff08876b34ab56" +
                "a1d425a1225833549adb841b51c9b317" +
                "6a272bdebba1d078478f62b397f33c8d";

        String actual = bytesToHex(key.getEncoded());
        assertEquals(expected, actual, "RFC 7914 test vector 2 failed");
    }

    /**
     * Test PBKDF2 with HmacSHA512.
     */
    @Test
    public void testPBKDF2_HmacSHA512() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA512");

        char[] password = "password".toCharArray();
        byte[] salt = "saltsalt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(32, key.getEncoded().length, "Key length should be 32 bytes");
    }

    /**
     * Test PBKDF2 with HmacSHA384.
     */
    @Test
    public void testPBKDF2_HmacSHA384() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA384");

        char[] password = "testpassword".toCharArray();
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0x42);
        int iterations = 5000;
        int keyLength = 384; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(48, key.getEncoded().length, "Key length should be 48 bytes");
    }

    /**
     * Test PBKDF2 with HmacSHA224.
     */
    @Test
    public void testPBKDF2_HmacSHA224() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA224");

        char[] password = "mypassword".toCharArray();
        byte[] salt = "mysalt".getBytes("ASCII");
        int iterations = 2000;
        int keyLength = 224; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(28, key.getEncoded().length, "Key length should be 28 bytes");
    }

    /**
     * Test PBKDF2 with empty password.
     */
    @Test
    public void testPBKDF2_EmptyPassword() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");

        char[] password = "".toCharArray();
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(32, key.getEncoded().length, "Key length should be 32 bytes");
    }

    /**
     * Test PBKDF2 with long password.
     */
    @Test
    public void testPBKDF2_LongPassword() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");

        // Create a 1000-character password
        char[] password = new char[1000];
        Arrays.fill(password, 'a');
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(32, key.getEncoded().length, "Key length should be 32 bytes");
    }

    /**
     * Test PBKDF2 with Unicode password.
     */
    @Test
    public void testPBKDF2_UnicodePassword() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");

        char[] password = "pāsswörd™".toCharArray();
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(32, key.getEncoded().length, "Key length should be 32 bytes");
    }

    /**
     * Test PBKDF2 with null password - PBEKeySpec treats null password as empty char[].
     * PBKDF2 should succeed with an empty password (RFC 2898 allows empty passwords).
     */
    @Test
    public void testPBKDF2_NullPassword() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");

        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        // PBEKeySpec(null, ...) stores null password as empty char[] - this is JDK behavior.
        // PBKDF2 with empty password is valid per RFC 2898.
        PBEKeySpec keySpec = new PBEKeySpec(null, salt, iterations, keyLength);
        SecretKey key = pbkdf2.deriveKey(keySpec);

        assertNotNull(key, "Derived key should not be null even with null/empty password");
        assertEquals(32, key.getEncoded().length, "Key length should be 32 bytes");
    }

    /**
     * Test PBKDF2 with null salt - PBEKeySpec constructor throws NullPointerException
     * for null salt in the 4-argument constructor.
     */
    @Test
    public void testPBKDF2_NullSalt() throws Exception {
        char[] password = "password".toCharArray();
        int iterations = 1000;
        int keyLength = 256; // bits

        // PBEKeySpec(password, null, iter, keyLen) throws NullPointerException
        assertThrows(NullPointerException.class, () -> {
            new PBEKeySpec(password, null, iterations, keyLength);
        }, "PBEKeySpec should throw NullPointerException for null salt");
    }

    /**
     * Test PBKDF2 with invalid iteration count - should throw exception.
     * PBEKeySpec itself validates iterationCount > 0 and throws IllegalArgumentException.
     */
    @Test
    public void testPBKDF2_InvalidIterationCount() throws Exception {
        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 0;
        int keyLength = 256; // bits

        // PBEKeySpec constructor throws IllegalArgumentException for iterationCount <= 0
        assertThrows(IllegalArgumentException.class, () -> {
            new PBEKeySpec(password, salt, iterations, keyLength);
        }, "PBEKeySpec should throw IllegalArgumentException for zero iteration count");
    }

    /**
     * Test PBKDF2 with invalid key length - should throw exception.
     * PBEKeySpec itself validates keyLength > 0 and throws IllegalArgumentException.
     */
    @Test
    public void testPBKDF2_InvalidKeyLength() throws Exception {
        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 0; // bits

        // PBEKeySpec constructor throws IllegalArgumentException for keyLength <= 0
        assertThrows(IllegalArgumentException.class, () -> {
            new PBEKeySpec(password, salt, iterations, keyLength);
        }, "PBEKeySpec should throw IllegalArgumentException for zero key length");
    }

    /**
     * Test PBKDF2 consistency - same inputs should produce same output.
     */
    @Test
    public void testPBKDF2_Consistency() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");

        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        PBEKeySpec keySpec1 = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key1 = pbkdf2.deriveKey(keySpec1);

        PBEKeySpec keySpec2 = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key2 = pbkdf2.deriveKey(keySpec2);

        assertArrayEquals(key1.getEncoded(), key2.getEncoded(),
                "Same inputs should produce same output");
    }

    /**
     * Test PBKDF2 with different salts produces different keys.
     */
    @Test
    public void testPBKDF2_DifferentSalts() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");

        char[] password = "password".toCharArray();
        byte[] salt1 = "salt1".getBytes("ASCII");
        byte[] salt2 = "salt2".getBytes("ASCII");
        int iterations = 1000;
        int keyLength = 256; // bits

        PBEKeySpec keySpec1 = new PBEKeySpec(password, salt1, iterations, keyLength);
        SecretKey key1 = pbkdf2.deriveKey(keySpec1);

        PBEKeySpec keySpec2 = new PBEKeySpec(password, salt2, iterations, keyLength);
        SecretKey key2 = pbkdf2.deriveKey(keySpec2);

        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()),
                "Different salts should produce different keys");
    }

    /**
     * Test getPRFAlgorithm method.
     */
    @Test
    public void testGetPRFAlgorithm() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");
        assertEquals("HmacSHA256", pbkdf2.getPRFAlgorithm());
    }

    /**
     * Test isFIPS method.
     */
    @Test
    public void testIsFIPS() throws Exception {
        OpenSSLPBKDF2 pbkdf2 = new OpenSSLPBKDF2(provider.getOpenSSLContext(), "HmacSHA256");
        // Result depends on provider FIPS mode
        boolean isFips = pbkdf2.isFIPS();
        assertTrue(isFips == provider.isFIPS());
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

