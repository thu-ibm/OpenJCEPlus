/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import com.ibm.crypto.plus.provider.openssl.OpenSSLGCMCipher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import javax.crypto.AEADBadTagException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test OpenSSL GCM implementation directly.
 * Tests the native OpenSSL GCM cipher wrapper without going through JCE.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLGCMCipher {

    private OpenSSLContext context;
    private SecureRandom random;

    // Test data
    private static final byte[] PLAINTEXT_16 = "1234567812345678".getBytes();
    private static final byte[] PLAINTEXT_128 = ("12345678123456781234567812345678123456781234567812345678123456781234567812345678" +
            "12345678123456781234567812345678123456781234567812345678").getBytes();
    private static final byte[] AAD_16 = "additionaldata16".getBytes();

    @BeforeAll
    public void setUp() throws Exception {
        // Initialize OpenSSL context
        context = OpenSSLContext.createContext(false); // non-FIPS mode
        random = new SecureRandom();
    }

    @Test
    public void testGCM_128_SingleShot_NoAAD() throws Exception {
        System.out.println("testGCM_128_SingleShot_NoAAD");

        // Generate key and IV
        byte[] key = new byte[16]; // 128-bit key
        byte[] iv = new byte[12];  // 96-bit IV (recommended)
        random.nextBytes(key);
        random.nextBytes(iv);

        // Create cipher
        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt
            cipher.initCipherEncrypt(key, iv);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
            int encLen = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext, 0);

            assertTrue(encLen > PLAINTEXT_16.length, "Ciphertext should include authentication tag");

            // Decrypt
            cipher.initCipherDecrypt(key, iv);
            byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
            int decLen = cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);

            assertEquals(PLAINTEXT_16.length, decLen, "Decrypted length should match plaintext");
            assertArrayEquals(PLAINTEXT_16, Arrays.copyOf(decrypted, decLen), "Decrypted text should match original");
        }
    }

    @Test
    public void testGCM_128_SingleShot_WithAAD() throws Exception {
        System.out.println("testGCM_128_SingleShot_WithAAD");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt with AAD
            cipher.initCipherEncrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
            int encLen = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext, 0);

            // Decrypt with AAD
            cipher.initCipherDecrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
            int decLen = cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);

            assertArrayEquals(PLAINTEXT_16, Arrays.copyOf(decrypted, decLen), "Decrypted text should match original");
        }
    }

    @Test
    public void testGCM_256_SingleShot() throws Exception {
        System.out.println("testGCM_256_SingleShot");

        byte[] key = new byte[32]; // 256-bit key
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 32)) {
            // Encrypt
            cipher.initCipherEncrypt(key, iv);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_128.length)];
            int encLen = cipher.doFinal(PLAINTEXT_128, 0, PLAINTEXT_128.length, ciphertext, 0);

            // Decrypt
            cipher.initCipherDecrypt(key, iv);
            byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
            int decLen = cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);

            assertArrayEquals(PLAINTEXT_128, Arrays.copyOf(decrypted, decLen), "Decrypted text should match original");
        }
    }

    @Test
    public void testGCM_MultiPart_NoAAD() throws Exception {
        System.out.println("testGCM_MultiPart_NoAAD");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt with update
            cipher.initCipherEncrypt(key, iv);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_128.length)];

            // Process in chunks
            int offset = 0;
            int chunk1 = 32;
            int len1 = cipher.update(PLAINTEXT_128, 0, chunk1, ciphertext, offset);
            offset += len1;

            int chunk2 = PLAINTEXT_128.length - chunk1;
            int len2 = cipher.doFinal(PLAINTEXT_128, chunk1, chunk2, ciphertext, offset);
            int totalEncLen = offset + len2;

            // Decrypt with update
            cipher.initCipherDecrypt(key, iv);
            byte[] decrypted = new byte[cipher.getOutputSize(totalEncLen)];

            offset = 0;
            int decChunk1 = 40;
            int decLen1 = cipher.update(ciphertext, 0, decChunk1, decrypted, offset);
            offset += decLen1;

            int decChunk2 = totalEncLen - decChunk1;
            int decLen2 = cipher.doFinal(ciphertext, decChunk1, decChunk2, decrypted, offset);
            int totalDecLen = offset + decLen2;

            assertArrayEquals(PLAINTEXT_128, Arrays.copyOf(decrypted, totalDecLen), "Decrypted text should match original");
        }
    }

    @Test
    public void testGCM_MultiPart_WithAAD() throws Exception {
        System.out.println("testGCM_MultiPart_WithAAD");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt
            cipher.initCipherEncrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_128.length)];

            int len1 = cipher.update(PLAINTEXT_128, 0, 64, ciphertext, 0);
            int len2 = cipher.doFinal(PLAINTEXT_128, 64, PLAINTEXT_128.length - 64, ciphertext, len1);
            int totalEncLen = len1 + len2;

            // Decrypt
            cipher.initCipherDecrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] decrypted = new byte[cipher.getOutputSize(totalEncLen)];

            int decLen1 = cipher.update(ciphertext, 0, 50, decrypted, 0);
            int decLen2 = cipher.doFinal(ciphertext, 50, totalEncLen - 50, decrypted, decLen1);
            int totalDecLen = decLen1 + decLen2;

            assertArrayEquals(PLAINTEXT_128, Arrays.copyOf(decrypted, totalDecLen), "Decrypted text should match original");
        }
    }

    @Test
    public void testGCM_TagVerification_WrongTag() throws Exception {
        System.out.println("testGCM_TagVerification_WrongTag");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt
            cipher.initCipherEncrypt(key, iv);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
            int encLen = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext, 0);

            // Corrupt the tag (last 16 bytes)
            ciphertext[encLen - 1] ^= 0x01;

            // Decrypt should fail
            cipher.initCipherDecrypt(key, iv);
            byte[] decrypted = new byte[cipher.getOutputSize(encLen)];

            assertThrows(AEADBadTagException.class, () -> {
                cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);
            }, "Should throw AEADBadTagException for corrupted tag");
        }
    }

    @Test
    public void testGCM_TagVerification_WrongAAD() throws Exception {
        System.out.println("testGCM_TagVerification_WrongAAD");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt with AAD
            cipher.initCipherEncrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
            int encLen = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext, 0);

            // Decrypt with different AAD
            byte[] wrongAAD = new byte[16];
            Arrays.fill(wrongAAD, (byte) 0xFF);

            cipher.initCipherDecrypt(key, iv);
            cipher.setAAD(wrongAAD);
            byte[] decrypted = new byte[cipher.getOutputSize(encLen)];

            assertThrows(AEADBadTagException.class, () -> {
                cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);
            }, "Should throw AEADBadTagException for wrong AAD");
        }
    }

    @Test
    public void testGCM_DifferentTagLengths() throws Exception {
        System.out.println("testGCM_DifferentTagLengths");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        // Test with 12-byte tag
        int[] tagLengths = {12, 13, 14, 15, 16};

        for (int tagLen : tagLengths) {
            try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
                cipher.setTagLen(tagLen);

                // Encrypt
                cipher.initCipherEncrypt(key, iv);
                byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
                int encLen = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext, 0);

                assertEquals(PLAINTEXT_16.length + tagLen, encLen,
                        "Ciphertext length should be plaintext + tag length");

                // Decrypt
                cipher.initCipherDecrypt(key, iv);
                byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
                int decLen = cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);

                assertArrayEquals(PLAINTEXT_16, Arrays.copyOf(decrypted, decLen),
                        "Decryption should work with " + tagLen + "-byte tag");
            }
        }
    }

    @Test
    public void testGCM_DifferentIVLengths() throws Exception {
        System.out.println("testGCM_DifferentIVLengths");

        byte[] key = new byte[16];

        // Test with different IV lengths (GCM supports various lengths)
        int[] ivLengths = {12, 16}; // 12 is recommended, 16 is also common

        for (int ivLen : ivLengths) {
            byte[] iv = new byte[ivLen];
            random.nextBytes(iv);

            try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
                // Encrypt
                cipher.initCipherEncrypt(key, iv);
                byte[] ciphertext = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
                int encLen = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext, 0);

                // Decrypt
                cipher.initCipherDecrypt(key, iv);
                byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
                int decLen = cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);

                assertArrayEquals(PLAINTEXT_16, Arrays.copyOf(decrypted, decLen),
                        "Decryption should work with " + ivLen + "-byte IV");
            }
        }
    }

    @Test
    public void testGCM_EmptyPlaintext() throws Exception {
        System.out.println("testGCM_EmptyPlaintext");

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // Encrypt empty plaintext with AAD
            cipher.initCipherEncrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] ciphertext = new byte[cipher.getOutputSize(0)];
            int encLen = cipher.doFinal(new byte[0], 0, 0, ciphertext, 0);

            assertEquals(16, encLen, "Should only contain authentication tag");

            // Decrypt
            cipher.initCipherDecrypt(key, iv);
            cipher.setAAD(AAD_16);
            byte[] decrypted = new byte[cipher.getOutputSize(encLen)];
            int decLen = cipher.doFinal(ciphertext, 0, encLen, decrypted, 0);

            assertEquals(0, decLen, "Decrypted length should be 0");
        }
    }

    @Test
    public void testGCM_ReuseAfterDoFinal() throws Exception {
        System.out.println("testGCM_ReuseAfterDoFinal");

        byte[] key = new byte[16];
        byte[] iv1 = new byte[12];
        byte[] iv2 = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv1);
        random.nextBytes(iv2);

        try (OpenSSLGCMCipher cipher = OpenSSLGCMCipher.getInstance(context, 16)) {
            // First encryption
            cipher.initCipherEncrypt(key, iv1);
            byte[] ciphertext1 = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
            int encLen1 = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext1, 0);

            // Second encryption with different IV
            cipher.initCipherEncrypt(key, iv2);
            byte[] ciphertext2 = new byte[cipher.getOutputSize(PLAINTEXT_16.length)];
            int encLen2 = cipher.doFinal(PLAINTEXT_16, 0, PLAINTEXT_16.length, ciphertext2, 0);

            // Ciphertexts should be different (different IVs)
            assertFalse(Arrays.equals(ciphertext1, ciphertext2),
                    "Ciphertexts with different IVs should differ");

            // Both should decrypt correctly
            cipher.initCipherDecrypt(key, iv1);
            byte[] decrypted1 = new byte[cipher.getOutputSize(encLen1)];
            cipher.doFinal(ciphertext1, 0, encLen1, decrypted1, 0);

            cipher.initCipherDecrypt(key, iv2);
            byte[] decrypted2 = new byte[cipher.getOutputSize(encLen2)];
            cipher.doFinal(ciphertext2, 0, encLen2, decrypted2, 0);

            assertArrayEquals(PLAINTEXT_16, Arrays.copyOf(decrypted1, PLAINTEXT_16.length));
            assertArrayEquals(PLAINTEXT_16, Arrays.copyOf(decrypted2, PLAINTEXT_16.length));
        }
    }
}
