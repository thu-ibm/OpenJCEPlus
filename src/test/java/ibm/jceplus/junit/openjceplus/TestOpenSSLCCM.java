/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.openssl.OpenSSLCCMCipher;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for OpenSSL CCM cipher implementation.
 * Tests basic encryption/decryption operations with various key sizes and tag lengths.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLCCM {

    private OpenSSLContext opensslContext;
    private SecureRandom random;

    @BeforeAll
    public void setUp() throws Exception {
        // Initialize OpenSSL context (non-FIPS for testing)
        opensslContext = OpenSSLContext.createContext(false);
        random = new SecureRandom();
    }

    @Test
    public void testCCM_AES128_BasicEncryptDecrypt() throws Exception {
        System.out.println("Testing AES-128-CCM basic encrypt/decrypt");

        // Test data
        byte[] plaintext = "Hello, OpenSSL CCM!".getBytes("UTF-8");
        byte[] key = new byte[16]; // 128-bit key
        byte[] iv = new byte[12];  // 96-bit nonce
        byte[] aad = "Additional Data".getBytes("UTF-8");
        int tagLen = 16; // 128-bit tag

        random.nextBytes(key);
        random.nextBytes(iv);

        // Encrypt
        OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        encryptCipher.init(true, key, iv, tagLen);

        byte[] ciphertext = new byte[plaintext.length + tagLen];
        int encLen = encryptCipher.doFinal(true, plaintext, 0, plaintext.length,
                ciphertext, 0, aad, tagLen);

        assertEquals(plaintext.length + tagLen, encLen, "Ciphertext length should include tag");

        // Decrypt
        OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        decryptCipher.init(false, key, iv, tagLen);

        byte[] decrypted = new byte[plaintext.length];
        int decLen = decryptCipher.doFinal(false, ciphertext, 0, encLen,
                decrypted, 0, aad, tagLen);

        assertEquals(plaintext.length, decLen, "Decrypted length should match plaintext");
        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");

        encryptCipher.close();
        decryptCipher.close();

        System.out.println("AES-128-CCM basic test passed");
    }

    @Test
    public void testCCM_AES192() throws Exception {
        System.out.println("Testing AES-192-CCM");

        byte[] plaintext = "Test AES-192-CCM".getBytes("UTF-8");
        byte[] key = new byte[24]; // 192-bit key
        byte[] iv = new byte[11];  // 88-bit nonce
        int tagLen = 12; // 96-bit tag

        random.nextBytes(key);
        random.nextBytes(iv);

        // Encrypt
        OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 24);
        encryptCipher.init(true, key, iv, tagLen);

        byte[] ciphertext = new byte[plaintext.length + tagLen];
        int encLen = encryptCipher.doFinal(true, plaintext, 0, plaintext.length,
                ciphertext, 0, null, tagLen);

        // Decrypt
        OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 24);
        decryptCipher.init(false, key, iv, tagLen);

        byte[] decrypted = new byte[plaintext.length];
        int decLen = decryptCipher.doFinal(false, ciphertext, 0, encLen,
                decrypted, 0, null, tagLen);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");

        encryptCipher.close();
        decryptCipher.close();

        System.out.println("AES-192-CCM test passed");
    }

    @Test
    public void testCCM_AES256() throws Exception {
        System.out.println("Testing AES-256-CCM");

        byte[] plaintext = "Test AES-256-CCM with longer text".getBytes("UTF-8");
        byte[] key = new byte[32]; // 256-bit key
        byte[] iv = new byte[13];  // 104-bit nonce (max for CCM)
        int tagLen = 16; // 128-bit tag

        random.nextBytes(key);
        random.nextBytes(iv);

        // Encrypt
        OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 32);
        encryptCipher.init(true, key, iv, tagLen);

        byte[] ciphertext = new byte[plaintext.length + tagLen];
        int encLen = encryptCipher.doFinal(true, plaintext, 0, plaintext.length,
                ciphertext, 0, null, tagLen);

        // Decrypt
        OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 32);
        decryptCipher.init(false, key, iv, tagLen);

        byte[] decrypted = new byte[plaintext.length];
        int decLen = decryptCipher.doFinal(false, ciphertext, 0, encLen,
                decrypted, 0, null, tagLen);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");

        encryptCipher.close();
        decryptCipher.close();

        System.out.println("AES-256-CCM test passed");
    }

    @Test
    public void testCCM_DifferentTagLengths() throws Exception {
        System.out.println("Testing CCM with different tag lengths");

        byte[] plaintext = "Test different tag lengths".getBytes("UTF-8");
        byte[] key = new byte[16];
        byte[] iv = new byte[12];

        random.nextBytes(key);
        random.nextBytes(iv);

        // Test various tag lengths (4, 6, 8, 10, 12, 14, 16 bytes)
        int[] tagLengths = {4, 6, 8, 10, 12, 14, 16};

        for (int tagLen : tagLengths) {
            System.out.println("  Testing tag length: " + tagLen + " bytes");

            // Encrypt
            OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
            encryptCipher.init(true, key, iv, tagLen);

            byte[] ciphertext = new byte[plaintext.length + tagLen];
            int encLen = encryptCipher.doFinal(true, plaintext, 0, plaintext.length,
                    ciphertext, 0, null, tagLen);

            assertEquals(plaintext.length + tagLen, encLen,
                    "Ciphertext length should include tag for tagLen=" + tagLen);

            // Decrypt
            OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
            decryptCipher.init(false, key, iv, tagLen);

            byte[] decrypted = new byte[plaintext.length];
            int decLen = decryptCipher.doFinal(false, ciphertext, 0, encLen,
                    decrypted, 0, null, tagLen);

            assertArrayEquals(plaintext, decrypted,
                    "Decrypted text should match original for tagLen=" + tagLen);

            encryptCipher.close();
            decryptCipher.close();
        }

        System.out.println("Different tag lengths test passed");
    }

    @Test
    public void testCCM_WithAAD() throws Exception {
        System.out.println("Testing CCM with AAD");

        byte[] plaintext = "Plaintext data".getBytes("UTF-8");
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        byte[] aad = "Additional Authenticated Data".getBytes("UTF-8");
        int tagLen = 16;

        random.nextBytes(key);
        random.nextBytes(iv);

        // Encrypt with AAD
        OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        encryptCipher.init(true, key, iv, tagLen);

        byte[] ciphertext = new byte[plaintext.length + tagLen];
        int encLen = encryptCipher.doFinal(true, plaintext, 0, plaintext.length,
                ciphertext, 0, aad, tagLen);

        // Decrypt with correct AAD
        OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        decryptCipher.init(false, key, iv, tagLen);

        byte[] decrypted = new byte[plaintext.length];
        int decLen = decryptCipher.doFinal(false, ciphertext, 0, encLen,
                decrypted, 0, aad, tagLen);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original with AAD");

        // Try to decrypt with wrong AAD (should fail)
        byte[] wrongAAD = "Wrong AAD".getBytes("UTF-8");
        OpenSSLCCMCipher decryptCipher2 = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        decryptCipher2.init(false, key, iv, tagLen);

        byte[] decrypted2 = new byte[plaintext.length];
        assertThrows(OpenSSLException.class, () -> {
            decryptCipher2.doFinal(false, ciphertext, 0, encLen,
                    decrypted2, 0, wrongAAD, tagLen);
        }, "Decryption should fail with wrong AAD");

        encryptCipher.close();
        decryptCipher.close();
        decryptCipher2.close();

        System.out.println("CCM with AAD test passed");
    }

    @Test
    public void testCCM_TagVerificationFailure() throws Exception {
        System.out.println("Testing CCM tag verification failure");

        byte[] plaintext = "Test tag verification".getBytes("UTF-8");
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        int tagLen = 16;

        random.nextBytes(key);
        random.nextBytes(iv);

        // Encrypt
        OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        encryptCipher.init(true, key, iv, tagLen);

        byte[] ciphertext = new byte[plaintext.length + tagLen];
        int encLen = encryptCipher.doFinal(true, plaintext, 0, plaintext.length,
                ciphertext, 0, null, tagLen);

        // Corrupt the tag
        ciphertext[ciphertext.length - 1] ^= 0x01;

        // Try to decrypt (should fail)
        OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        decryptCipher.init(false, key, iv, tagLen);

        byte[] decrypted = new byte[plaintext.length];
        assertThrows(OpenSSLException.class, () -> {
            decryptCipher.doFinal(false, ciphertext, 0, encLen,
                    decrypted, 0, null, tagLen);
        }, "Decryption should fail with corrupted tag");

        encryptCipher.close();
        decryptCipher.close();

        System.out.println("Tag verification failure test passed");
    }

    @Test
    public void testCCM_EmptyPlaintext() throws Exception {
        System.out.println("Testing CCM with empty plaintext");

        byte[] plaintext = new byte[0];
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        byte[] aad = "Only AAD, no plaintext".getBytes("UTF-8");
        int tagLen = 16;

        random.nextBytes(key);
        random.nextBytes(iv);

        // Encrypt
        OpenSSLCCMCipher encryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        encryptCipher.init(true, key, iv, tagLen);

        byte[] ciphertext = new byte[tagLen];
        int encLen = encryptCipher.doFinal(true, plaintext, 0, 0,
                ciphertext, 0, aad, tagLen);

        assertEquals(tagLen, encLen, "Output should only contain tag");

        // Decrypt
        OpenSSLCCMCipher decryptCipher = OpenSSLCCMCipher.getInstance(opensslContext, 16);
        decryptCipher.init(false, key, iv, tagLen);

        byte[] decrypted = new byte[0];
        int decLen = decryptCipher.doFinal(false, ciphertext, 0, encLen,
                decrypted, 0, aad, tagLen);

        assertEquals(0, decLen, "Decrypted length should be 0");

        encryptCipher.close();
        decryptCipher.close();

        System.out.println("Empty plaintext test passed");
    }
}
