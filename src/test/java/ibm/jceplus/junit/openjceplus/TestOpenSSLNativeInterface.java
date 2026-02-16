/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class to exercise the OpenSSL functionality through the JCE provider API.
 * This test focuses on verifying that the OpenSSL library is properly loaded
 * and that basic cryptographic operations work correctly.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLNativeInterface {

    private static final String PROVIDER_NAME = "OpenJCEPlus";

    // Test input data
    private static final byte[] TEST_INPUT = "Hello, OpenSSL!".getBytes(StandardCharsets.UTF_8);

    // Expected SHA-256 hash value for the test input
    // This value was obtained from the actual output of the OpenJCEPlus provider
    private static final String EXPECTED_SHA256_HEX =
            "63ee7f365450f9586dbb31c9b59db63817797e04ea1014dd5a8ac6615d44fac1";

    @BeforeAll
    public void setUp() {
        // Load the OpenJCEPlus provider
        Utils.loadProviderTestSuite();
    }

    /**
     * Test to verify that the OpenJCEPlus provider is properly loaded
     * and has the expected algorithms.
     */
    @Test
    public void testProviderAvailability() {
        // Get the OpenJCEPlus provider
        Provider provider = Security.getProvider(PROVIDER_NAME);
        assertNotNull(provider, "OpenJCEPlus provider should be available");

        // Check if the provider is the correct class
        String expectedClassName = "com.ibm.crypto.plus.provider.OpenJCEPlus";
        assertEquals(expectedClassName, provider.getClass().getName(),
                "Provider should be an instance of OpenJCEPlus");

        // Check that the provider has the expected algorithms
        Set<Provider.Service> services = provider.getServices();

        // Check for SHA-256 algorithm
        boolean hasSHA256 = services.stream()
                .anyMatch(service -> service.getAlgorithm().equals("SHA-256"));
        assertTrue(hasSHA256, "Provider should support SHA-256 algorithm");

        // Check for AES algorithm
        boolean hasAES = services.stream()
                .anyMatch(service -> service.getAlgorithm().equals("AES"));
        assertTrue(hasAES, "Provider should support AES algorithm");

        // Check for RSA algorithm
        boolean hasRSA = services.stream()
                .anyMatch(service -> service.getAlgorithm().equals("RSA"));
        assertTrue(hasRSA, "Provider should support RSA algorithm");

        // Check for SHA256DRBG algorithm
        boolean hasSHA256DRBG = services.stream()
                .anyMatch(service -> service.getAlgorithm().equals("SHA256DRBG"));
        assertTrue(hasSHA256DRBG, "Provider should support SHA256DRBG algorithm");
    }

    /**
     * Test to verify that the SHA-256 message digest works correctly.
     * This indirectly tests the OpenSSL implementation.
     */
    @Test
    public void testSHA256MessageDigest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256", PROVIDER_NAME);
        assertNotNull(md, "SHA-256 MessageDigest should be available");

        // Test with the input
        byte[] digest = md.digest(TEST_INPUT);
        assertNotNull(digest, "Digest should not be null");

        // Convert the digest to hex string for comparison
        String digestHex = bytesToHex(digest);
        assertEquals(EXPECTED_SHA256_HEX, digestHex, "SHA-256 digest should match expected value");

        // Test incremental update
        md.reset();
        md.update(TEST_INPUT, 0, 7); // "Hello, "
        md.update(TEST_INPUT, 7, TEST_INPUT.length - 7); // "OpenSSL!"
        byte[] digest2 = md.digest();
        String digest2Hex = bytesToHex(digest2);
        assertEquals(EXPECTED_SHA256_HEX, digest2Hex, "SHA-256 digest with incremental updates should match expected value");
    }

    /**
     * Test to verify that the SecureRandom implementation works correctly.
     * This indirectly tests the OpenSSL random number generation.
     */
    @Test
    public void testSecureRandom() throws Exception {
        // Use SHA256DRBG which is supported by the provider
        SecureRandom random = SecureRandom.getInstance("SHA256DRBG", PROVIDER_NAME);
        assertNotNull(random, "SecureRandom should be available");

        // Generate some random bytes
        byte[] randomBytes1 = new byte[32];
        random.nextBytes(randomBytes1);

        // Generate more random bytes
        byte[] randomBytes2 = new byte[32];
        random.nextBytes(randomBytes2);

        // The two random byte arrays should be different
        boolean allZeros1 = true;
        boolean allZeros2 = true;
        boolean identical = true;

        for (int i = 0; i < randomBytes1.length; i++) {
            if (randomBytes1[i] != 0) allZeros1 = false;
            if (randomBytes2[i] != 0) allZeros2 = false;
            if (randomBytes1[i] != randomBytes2[i]) identical = false;
        }

        assertTrue(!allZeros1, "First random bytes should not be all zeros");
        assertTrue(!allZeros2, "Second random bytes should not be all zeros");
        assertTrue(!identical, "Random byte arrays should be different");
    }

    /**
     * Test to verify that the AES cipher works correctly.
     * This indirectly tests the OpenSSL cipher implementation.
     */
    @Test
    public void testAESCipher() throws Exception {
        // Create a key
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES", PROVIDER_NAME);
        keyGen.init(256);
        javax.crypto.SecretKey key = keyGen.generateKey();

        // Create a cipher
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER_NAME);

        // Initialize the cipher for encryption
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);

        // Get the IV
        byte[] iv = cipher.getIV();
        assertNotNull(iv, "IV should not be null");
        assertEquals(16, iv.length, "IV length should be 16 bytes for AES");

        // Encrypt the data
        byte[] encrypted = cipher.doFinal(TEST_INPUT);
        assertNotNull(encrypted, "Encrypted data should not be null");

        // Initialize the cipher for decryption
        javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);

        // Decrypt the data
        byte[] decrypted = cipher.doFinal(encrypted);
        assertNotNull(decrypted, "Decrypted data should not be null");

        // Verify that the decrypted data matches the original
        assertEquals(new String(TEST_INPUT, StandardCharsets.UTF_8),
                new String(decrypted, StandardCharsets.UTF_8),
                "Decrypted data should match original");
    }

    /**
     * Helper method to convert a byte array to a hex string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
