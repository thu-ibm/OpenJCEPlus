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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for OpenSSL KeyWrap native implementation.
 * 
 * This test validates the native OpenSSL key wrap/unwrap functionality
 * implemented in OpenSSLKeyWrap.c, which provides AES Key Wrap (RFC 3394)
 * and AES Key Wrap with Padding (RFC 5649) support.
 * 
 * The native implementation supports:
 * - AES-128, AES-192, and AES-256 key encryption keys (KEK)
 * - Standard key wrap (id-aes128-wrap, id-aes192-wrap, id-aes256-wrap)
 * - Key wrap with padding (id-aes128-wrap-pad, id-aes192-wrap-pad, id-aes256-wrap-pad)
 * 
 * Test coverage includes:
 * - Basic wrap/unwrap operations with different key sizes
 * - Wrap/unwrap with padding enabled
 * - Round-trip testing (wrap then unwrap)
 * - Error conditions (invalid keys, corrupted ciphertext)
 * - FIPS and non-FIPS modes
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLKeyWrap {

    private String providerName;

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        providerName = Utils.TEST_SUITE_PROVIDER_NAME;
    }

    /**
     * Test basic AES key wrap with 128-bit KEK
     */
    @Test
    public void testAESKeyWrap128() throws Exception {
        SecretKey kek = generateKey("AES", 128);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test basic AES key wrap with 192-bit KEK
     */
    @Test
    public void testAESKeyWrap192() throws Exception {
        SecretKey kek = generateKey("AES", 192);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test basic AES key wrap with 256-bit KEK
     */
    @Test
    public void testAESKeyWrap256() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 256);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test AES key wrap with padding for various key sizes
     */
    @ParameterizedTest
    @CsvSource({
        "128, 128",
        "128, 192",
        "128, 256",
        "192, 128",
        "192, 256",
        "256, 128",
        "256, 256"
    })
    public void testAESKeyWrapWithPadding(int kekSize, int keySize) throws Exception {
        SecretKey kek = generateKey("AES", kekSize);
        SecretKey keyToWrap = generateKey("AES", keySize);
        
        testWrapUnwrap("AES/KWP/NoPadding", kek, keyToWrap);
    }

    /**
     * Test wrapping keys of various sizes without padding
     */
    @ParameterizedTest
    @CsvSource({
        "128, 128",
        "192, 128",
        "192, 192",
        "256, 128",
        "256, 192",
        "256, 256"
    })
    public void testAESKeyWrapVariousSizes(int kekSize, int keySize) throws Exception {
        SecretKey kek = generateKey("AES", kekSize);
        SecretKey keyToWrap = generateKey("AES", keySize);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test that corrupted wrapped key fails to unwrap
     */
    @Test
    public void testCorruptedWrappedKey() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        // Corrupt the wrapped key
        wrappedKey[5] ^= 0xFF;
        
        cipher.init(Cipher.UNWRAP_MODE, kek);
        
        assertThrows(Exception.class, () -> {
            cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        }, "Unwrapping corrupted key should fail");
    }

    /**
     * Test that using wrong KEK fails to unwrap
     */
    @Test
    public void testWrongKEK() throws Exception {
        SecretKey kek1 = generateKey("AES", 256);
        SecretKey kek2 = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek1);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        cipher.init(Cipher.UNWRAP_MODE, kek2);
        
        assertThrows(Exception.class, () -> {
            cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        }, "Unwrapping with wrong KEK should fail");
    }

    /**
     * Test wrap/unwrap with null key should fail
     */
    @Test
    public void testNullKey() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        
        assertThrows(Exception.class, () -> {
            cipher.init(Cipher.WRAP_MODE, (Key) null);
        }, "Initializing with null key should fail");
    }

    /**
     * Test that wrapped key length is correct
     * Standard key wrap adds 8 bytes (64 bits) to the input
     */
    @Test
    public void testWrappedKeyLength() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        // Wrapped key should be 8 bytes longer than original
        assertEquals(keyToWrap.getEncoded().length + 8, wrappedKey.length,
            "Wrapped key length should be original length + 8 bytes");
    }

    /**
     * Test that wrapped key with padding has correct length
     * Padded key wrap output is always a multiple of 8 bytes
     */
    @Test
    public void testWrappedKeyLengthWithPadding() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KWP/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        // Wrapped key length should be multiple of 8
        assertEquals(0, wrappedKey.length % 8,
            "Wrapped key with padding should have length multiple of 8");
        
        // Should be at least 8 bytes longer than original
        assertTrue(wrappedKey.length >= keyToWrap.getEncoded().length + 8,
            "Wrapped key should be at least 8 bytes longer than original");
    }

    /**
     * Test multiple wrap/unwrap operations with same cipher instance
     */
    @Test
    public void testMultipleOperations() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        
        for (int i = 0; i < 10; i++) {
            SecretKey keyToWrap = generateKey("AES", 128);
            
            cipher.init(Cipher.WRAP_MODE, kek);
            byte[] wrappedKey = cipher.wrap(keyToWrap);
            
            cipher.init(Cipher.UNWRAP_MODE, kek);
            Key unwrappedKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            
            assertArrayEquals(keyToWrap.getEncoded(), unwrappedKey.getEncoded(),
                "Iteration " + i + ": Keys should match after wrap/unwrap");
        }
    }

    /**
     * Helper method to test wrap and unwrap operations
     */
    private void testWrapUnwrap(String algorithm, SecretKey kek, SecretKey keyToWrap) 
            throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm, providerName);
        
        // Wrap the key
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        assertNotNull(wrappedKey, "Wrapped key should not be null");
        assertTrue(wrappedKey.length > 0, "Wrapped key should have non-zero length");
        
        // Unwrap the key
        cipher.init(Cipher.UNWRAP_MODE, kek);
        Key unwrappedKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        
        assertNotNull(unwrappedKey, "Unwrapped key should not be null");
        assertArrayEquals(keyToWrap.getEncoded(), unwrappedKey.getEncoded(),
            "Original and unwrapped keys should match");
    }

    /**
     * Helper method to generate a secret key
     */
    private SecretKey generateKey(String algorithm, int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, providerName);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }
}


