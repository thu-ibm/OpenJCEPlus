/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.openssl.OpenSSLContext;
import com.ibm.crypto.plus.provider.openssl.OpenSSLHMAC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for verifying OpenSSL HMAC implementation.
 * This test ensures that the HMAC class correctly uses OpenSSL when available.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLHMAC {

    private static OpenJCEPlus provider;
    private static boolean opensslAvailable = false;
    private static OpenSSLContext opensslContext;

    // Test vectors from RFC 4231 (HMAC-SHA-256)
    private static final byte[] KEY_1 = hexStringToByteArray(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    private static final byte[] DATA_1 = "Hi There".getBytes();
    private static final byte[] HMAC_SHA256_1 = hexStringToByteArray(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    private static final byte[] KEY_2 = "Jefe".getBytes();
    private static final byte[] DATA_2 = "what do ya want for nothing?".getBytes();
    private static final byte[] HMAC_SHA256_2 = hexStringToByteArray(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    private static final byte[] KEY_3 = hexStringToByteArray(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    private static final byte[] DATA_3 = new byte[50];
    static {
        Arrays.fill(DATA_3, (byte) 0xdd);
    }
    private static final byte[] HMAC_SHA256_3 = hexStringToByteArray(
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    // Test vector for SHA-1
    private static final byte[] HMAC_SHA1_1 = hexStringToByteArray(
        "b617318655057264e28bc0b6fb378c8ef146be00");

    // Test vector for SHA-512
    private static final byte[] HMAC_SHA512_1 = hexStringToByteArray(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();

        // Check if OpenSSL is available
        try {
            provider = (OpenJCEPlus) Security.getProvider(Utils.TEST_SUITE_PROVIDER_NAME);
            if (provider == null) {
                provider = new OpenJCEPlus();
                Security.addProvider(provider);
            }

            opensslContext = provider.getOpenSSLContext();
            opensslAvailable = (opensslContext != null);
            System.out.println("OpenSSL available for HMAC: " + opensslAvailable);
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
     * Test that verifies OpenSSL is available for HMAC operations.
     */
    @Test
    public void testOpenSSLAvailable() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        assertNotNull(opensslContext, "OpenSSL context should not be null");
        assertNotNull(provider, "Provider should not be null");
    }

    /**
     * Test OpenSSL HMAC-SHA256 with test vector 1
     */
    @Test
    public void testOpenSSLHmacSHA256_Vector1() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        assertNotNull(hmac, "HMAC instance should not be null");

        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA256");
        hmac.engineInit(key, null);
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result = hmac.engineDoFinal();

        assertArrayEquals(HMAC_SHA256_1, result,
                "HMAC-SHA256 should match RFC 4231 test vector 1");
    }

    /**
     * Test OpenSSL HMAC-SHA256 with test vector 2
     */
    @Test
    public void testOpenSSLHmacSHA256_Vector2() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_2, "HmacSHA256");
        hmac.engineInit(key, null);
        hmac.engineUpdate(DATA_2, 0, DATA_2.length);
        byte[] result = hmac.engineDoFinal();

        assertArrayEquals(HMAC_SHA256_2, result,
                "HMAC-SHA256 should match RFC 4231 test vector 2");
    }

    /**
     * Test OpenSSL HMAC-SHA256 with test vector 3
     */
    @Test
    public void testOpenSSLHmacSHA256_Vector3() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_3, "HmacSHA256");
        hmac.engineInit(key, null);
        hmac.engineUpdate(DATA_3, 0, DATA_3.length);
        byte[] result = hmac.engineDoFinal();

        assertArrayEquals(HMAC_SHA256_3, result,
                "HMAC-SHA256 should match RFC 4231 test vector 3");
    }

    /**
     * Test OpenSSL HMAC-SHA1
     */
    @Test
    public void testOpenSSLHmacSHA1() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA1(opensslContext);
        assertNotNull(hmac, "HMAC-SHA1 instance should not be null");

        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA1");
        hmac.engineInit(key, null);
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result = hmac.engineDoFinal();

        assertArrayEquals(HMAC_SHA1_1, result,
                "HMAC-SHA1 should match RFC 2202 test vector");
    }

    /**
     * Test OpenSSL HMAC-SHA512
     */
    @Test
    public void testOpenSSLHmacSHA512() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA512(opensslContext);
        assertNotNull(hmac, "HMAC-SHA512 instance should not be null");

        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA512");
        hmac.engineInit(key, null);
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result = hmac.engineDoFinal();

        assertArrayEquals(HMAC_SHA512_1, result,
                "HMAC-SHA512 should match RFC 4231 test vector");
    }

    /**
     * Test OpenSSL HMAC with incremental updates
     */
    @Test
    public void testOpenSSLHmacIncrementalUpdate() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_2, "HmacSHA256");
        hmac.engineInit(key, null);

        // Update in chunks
        byte[] part1 = "what do ya ".getBytes();
        byte[] part2 = "want for ".getBytes();
        byte[] part3 = "nothing?".getBytes();

        hmac.engineUpdate(part1, 0, part1.length);
        hmac.engineUpdate(part2, 0, part2.length);
        hmac.engineUpdate(part3, 0, part3.length);

        byte[] result = hmac.engineDoFinal();

        assertArrayEquals(HMAC_SHA256_2, result,
                "HMAC with incremental updates should match test vector");
    }

    /**
     * Test OpenSSL HMAC reset functionality
     */
    @Test
    public void testOpenSSLHmacReset() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA256");
        hmac.engineInit(key, null);

        // First computation
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result1 = hmac.engineDoFinal();

        // After doFinal, HMAC should be reset automatically
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result2 = hmac.engineDoFinal();

        assertArrayEquals(result1, result2,
                "HMAC should produce same result after automatic reset");

        // Test explicit reset
        hmac.engineUpdate("partial data".getBytes(), 0, 12);
        hmac.engineReset();
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result3 = hmac.engineDoFinal();

        assertArrayEquals(result1, result3,
                "HMAC should produce same result after explicit reset");
    }

    /**
     * Test OpenSSL HMAC with empty data
     */
    @Test
    public void testOpenSSLHmacEmptyData() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA256");
        hmac.engineInit(key, null);

        byte[] result = hmac.engineDoFinal();
        assertNotNull(result, "HMAC of empty data should not be null");
        assertEquals(32, result.length, "HMAC-SHA256 should produce 32 bytes");
    }

    /**
     * Test OpenSSL HMAC MAC length
     */
    @Test
    public void testOpenSSLHmacMacLength() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmacSHA1 = OpenSSLHMAC.getInstanceHmacSHA1(opensslContext);
        assertEquals(20, hmacSHA1.engineGetMacLength(), "HMAC-SHA1 should be 20 bytes");

        OpenSSLHMAC hmacSHA256 = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        assertEquals(32, hmacSHA256.engineGetMacLength(), "HMAC-SHA256 should be 32 bytes");

        OpenSSLHMAC hmacSHA384 = OpenSSLHMAC.getInstanceHmacSHA384(opensslContext);
        assertEquals(48, hmacSHA384.engineGetMacLength(), "HMAC-SHA384 should be 48 bytes");

        OpenSSLHMAC hmacSHA512 = OpenSSLHMAC.getInstanceHmacSHA512(opensslContext);
        assertEquals(64, hmacSHA512.engineGetMacLength(), "HMAC-SHA512 should be 64 bytes");
    }

    /**
     * Test OpenSSL HMAC with single byte update
     */
    @Test
    public void testOpenSSLHmacSingleByteUpdate() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA256");
        hmac.engineInit(key, null);

        // Update byte by byte
        for (byte b : DATA_1) {
            hmac.engineUpdate(b);
        }

        byte[] result = hmac.engineDoFinal();
        assertArrayEquals(HMAC_SHA256_1, result,
                "HMAC with single byte updates should match test vector");
    }

    /**
     * Test OpenSSL HMAC error handling - null key
     */
    @Test
    public void testOpenSSLHmacNullKey() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        
        assertThrows(Exception.class, () -> {
            hmac.engineInit(null, null);
        }, "Should throw exception for null key");
    }

    /**
     * Test OpenSSL HMAC error handling - uninitialized
     */
    @Test
    public void testOpenSSLHmacUninitialized() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        
        assertThrows(IllegalStateException.class, () -> {
            hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        }, "Should throw exception when not initialized");
    }

    /**
     * Test OpenSSL HMAC with large data
     */
    @Test
    public void testOpenSSLHmacLargeData() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA256");
        hmac.engineInit(key, null);

        // Create large data (1MB)
        byte[] largeData = new byte[1024 * 1024];
        Arrays.fill(largeData, (byte) 0x42);

        hmac.engineUpdate(largeData, 0, largeData.length);
        byte[] result = hmac.engineDoFinal();

        assertNotNull(result, "HMAC of large data should not be null");
        assertEquals(32, result.length, "HMAC-SHA256 should produce 32 bytes");
    }

    /**
     * Test OpenSSL HMAC dispose functionality
     */
    @Test
    public void testOpenSSLHmacDispose() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        OpenSSLHMAC hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
        SecretKeySpec key = new SecretKeySpec(KEY_1, "HmacSHA256");
        hmac.engineInit(key, null);
        hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        byte[] result = hmac.engineDoFinal();

        assertNotNull(result, "HMAC should produce result before dispose");

        // Dispose the HMAC
        hmac.dispose();

        // After dispose, operations should fail
        assertThrows(IllegalStateException.class, () -> {
            hmac.engineUpdate(DATA_1, 0, DATA_1.length);
        }, "Should throw exception after dispose");
    }

    /**
     * Test all supported HMAC algorithms
     */
    @Test
    public void testAllOpenSSLHmacAlgorithms() throws Exception {
        if (!opensslAvailable) {
            System.out.println("Skipping test as OpenSSL is not available");
            return;
        }

        String[] algorithms = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
                               "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};

        for (String algo : algorithms) {
            try {
                OpenSSLHMAC hmac = null;
                switch (algo) {
                    case "MD5":
                        hmac = OpenSSLHMAC.getInstanceHmacMD5(opensslContext);
                        break;
                    case "SHA1":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA1(opensslContext);
                        break;
                    case "SHA224":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA224(opensslContext);
                        break;
                    case "SHA256":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA256(opensslContext);
                        break;
                    case "SHA384":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA384(opensslContext);
                        break;
                    case "SHA512":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA512(opensslContext);
                        break;
                    case "SHA3-224":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA3_224(opensslContext);
                        break;
                    case "SHA3-256":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA3_256(opensslContext);
                        break;
                    case "SHA3-384":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA3_384(opensslContext);
                        break;
                    case "SHA3-512":
                        hmac = OpenSSLHMAC.getInstanceHmacSHA3_512(opensslContext);
                        break;
                }

                assertNotNull(hmac, "HMAC-" + algo + " instance should not be null");

                SecretKeySpec key = new SecretKeySpec(KEY_1, "Hmac" + algo);
                hmac.engineInit(key, null);
                hmac.engineUpdate(DATA_1, 0, DATA_1.length);
                byte[] result = hmac.engineDoFinal();

                assertNotNull(result, "HMAC-" + algo + " should produce result");
                assertTrue(result.length > 0, "HMAC-" + algo + " result should not be empty");

                System.out.println("HMAC-" + algo + " test passed, MAC length: " + result.length);
            } catch (Exception e) {
                System.out.println("HMAC-" + algo + " not supported or failed: " + e.getMessage());
            }
        }
    }

    /**
     * Helper method to convert hex string to byte array
     */
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}


