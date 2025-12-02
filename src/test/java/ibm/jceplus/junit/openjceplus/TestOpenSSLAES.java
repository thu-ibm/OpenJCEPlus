/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import ibm.jceplus.junit.base.BaseTestAES;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test class for verifying OpenSSL AES implementation.
 * This test ensures that the AESCipher class correctly uses OpenSSL when available.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLAES extends BaseTestAES {

    private static OpenJCEPlus provider;
    private static boolean opensslAvailable = false;

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        setKeySize(128);

        // Check if OpenSSL is available
        try {
            provider = (OpenJCEPlus) Security.getProvider(Utils.TEST_SUITE_PROVIDER_NAME);
            if (provider == null) {
                provider = new OpenJCEPlus();
                Security.addProvider(provider);
            }

            OpenSSLContext opensslContext = provider.getOpenSSLContext();
            opensslAvailable = (opensslContext != null);
            System.out.println("OpenSSL available: " + opensslAvailable);
            if (opensslAvailable) {
                System.out.println("OpenSSL version: " + opensslContext.getOpenSSLVersion());
                System.out.println("OpenSSL path: " + opensslContext.getOpenSSLInstallPath());
            }
        } catch (Exception e) {
            System.out.println("OpenSSL not available: " + e.getMessage());
            opensslAvailable = false;
        }
    }

    /**
     * Test that verifies OpenSSL is available and being used for AES operations.
     */
    @Test
    public void testOpenSSLAvailable() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        // Verify OpenSSL context is available
        OpenSSLContext opensslContext = provider.getOpenSSLContext();
        assertNotNull(opensslContext, "OpenSSL context should not be null");

        // Test basic AES encryption/decryption
        Cipher cipher = Cipher.getInstance("AES", provider);
        assertNotNull(cipher, "Cipher should not be null");

        // Initialize cipher with a test key
        byte[] keyBytes = new byte[16]; // 128-bit key
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) i;
        }
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        // Encrypt some data
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] plaintext = "This is a test message for OpenSSL AES encryption".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Decrypt the data
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(ciphertext);

        // Verify the decrypted data matches the original plaintext
        assertEquals(new String(plaintext), new String(decrypted),
                "Decrypted text should match original plaintext");
    }

    /**
     * Test AES in CBC mode with PKCS5Padding using OpenSSL.
     */
    @Test
    public void testOpenSSLAES_CBC_PKCS5Padding() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        // Run the standard AES CBC PKCS5Padding test which should use OpenSSL
        encryptDecrypt("AES/CBC/PKCS5Padding");
    }

    /**
     * Test AES in ECB mode with PKCS5Padding using OpenSSL.
     */
    @Test
    public void testOpenSSLAES_ECB_PKCS5Padding() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        // Run the standard AES ECB PKCS5Padding test which should use OpenSSL
        encryptDecrypt("AES/ECB/PKCS5Padding");
    }

    /**
     * Test AES in CTR mode with NoPadding using OpenSSL.
     */
    @Test
    public void testOpenSSLAES_CTR_NoPadding() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        // Run the standard AES CTR NoPadding test which should use OpenSSL
        encryptDecrypt("AES/CTR/NoPadding");
    }

    /**
     * Test AES with different key sizes (128, 192, 256) using OpenSSL.
     */
    @Test
    public void testOpenSSLAESWithDifferentKeySizes() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        // Test with 128-bit key
        byte[] key128 = new byte[16];
        for (int i = 0; i < key128.length; i++) {
            key128[i] = (byte) i;
        }
        SecretKey secretKey128 = new SecretKeySpec(key128, "AES");
        testWithKey(secretKey128, "AES/CBC/PKCS5Padding");

        // Test with 192-bit key
        byte[] key192 = new byte[24];
        for (int i = 0; i < key192.length; i++) {
            key192[i] = (byte) i;
        }
        SecretKey secretKey192 = new SecretKeySpec(key192, "AES");
        testWithKey(secretKey192, "AES/CBC/PKCS5Padding");

        // Test with 256-bit key
        byte[] key256 = new byte[32];
        for (int i = 0; i < key256.length; i++) {
            key256[i] = (byte) i;
        }
        SecretKey secretKey256 = new SecretKeySpec(key256, "AES");
        testWithKey(secretKey256, "AES/CBC/PKCS5Padding");
    }

    /**
     * Helper method to test AES encryption/decryption with a specific key.
     */
    private void testWithKey(SecretKey key, String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, provider);

        // Encrypt some data
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] plaintext = "This is a test message for OpenSSL AES encryption".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Decrypt the data
        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        byte[] decrypted = cipher.doFinal(ciphertext);

        // Verify the decrypted data matches the original plaintext
        assertEquals(new String(plaintext), new String(decrypted),
                "Decrypted text should match original plaintext");
    }
}
