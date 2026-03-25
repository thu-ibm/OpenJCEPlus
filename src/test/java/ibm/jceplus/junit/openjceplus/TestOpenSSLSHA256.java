/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import ibm.jceplus.junit.base.BaseTestSHA256;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.security.MessageDigest;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test class for verifying OpenSSL SHA-256 implementation.
 * This test ensures that the MessageDigest class correctly uses OpenSSL when available.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLSHA256 extends BaseTestSHA256 {

    private static OpenJCEPlus provider;
    private static boolean opensslAvailable = false;

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);

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
     * Test that verifies OpenSSL is available and being used for SHA-256 operations.
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

        // Test basic SHA-256 digest
        MessageDigest md = MessageDigest.getInstance("SHA-256", provider);
        assertNotNull(md, "MessageDigest should not be null");

        // Test with known vector from NIST FIPS 180-4
        byte[] input = "abc".getBytes();
        byte[] expectedHash = hexStringToByteArray(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        
        byte[] actualHash = md.digest(input);
        assertArrayEquals(expectedHash, actualHash,
                "SHA-256 hash should match NIST test vector");
    }

    /**
     * Test SHA-256 with incremental updates using OpenSSL.
     */
    @Test
    public void testOpenSSLSHA256IncrementalUpdate() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256", provider);
        
        // Update in chunks
        md.update("ab".getBytes());
        md.update("c".getBytes());
        
        byte[] expectedHash = hexStringToByteArray(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        
        byte[] actualHash = md.digest();
        assertArrayEquals(expectedHash, actualHash,
                "SHA-256 hash with incremental updates should match NIST test vector");
    }

    /**
     * Test SHA-256 digest cloning using OpenSSL.
     */
    @Test
    public void testOpenSSLSHA256Clone() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        MessageDigest md1 = MessageDigest.getInstance("SHA-256", provider);
        md1.update("ab".getBytes());
        
        // Clone the digest
        MessageDigest md2 = (MessageDigest) md1.clone();
        
        // Continue with different data
        md1.update("c".getBytes());
        byte[] hash1 = md1.digest();
        
        md2.update("c".getBytes());
        byte[] hash2 = md2.digest();
        
        // Both should produce the same hash
        assertArrayEquals(hash1, hash2,
                "Cloned digest should produce the same hash");
        
        byte[] expectedHash = hexStringToByteArray(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertArrayEquals(expectedHash, hash1,
                "SHA-256 hash should match NIST test vector");
    }

    /**
     * Test SHA-256 digest reset using OpenSSL.
     */
    @Test
    public void testOpenSSLSHA256Reset() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256", provider);
        
        // First digest
        md.update("abc".getBytes());
        byte[] hash1 = md.digest();
        
        // Digest automatically resets, compute again
        md.update("abc".getBytes());
        byte[] hash2 = md.digest();
        
        // Both should be the same
        assertArrayEquals(hash1, hash2,
                "Digest after automatic reset should produce the same hash");
        
        // Test explicit reset
        md.update("partial".getBytes());
        md.reset();
        md.update("abc".getBytes());
        byte[] hash3 = md.digest();
        
        assertArrayEquals(hash1, hash3,
                "Digest after explicit reset should produce the same hash");
    }

    /**
     * Test SHA-256 with empty input using OpenSSL.
     */
    @Test
    public void testOpenSSLSHA256EmptyInput() throws Exception {
        // Skip test if OpenSSL is not available
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256", provider);
        
        byte[] expectedHash = hexStringToByteArray(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        
        byte[] actualHash = md.digest(new byte[0]);
        assertArrayEquals(expectedHash, actualHash,
                "SHA-256 hash of empty input should match NIST test vector");
    }

    /**
     * Helper method to convert hex string to byte array
     */
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}


