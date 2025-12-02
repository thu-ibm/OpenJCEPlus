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
import ibm.jceplus.junit.base.BaseTestAESInterop;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.security.Security;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Test class for verifying OpenSSL AES 256-bit interoperability with SunJCE provider.
 * This test ensures that AES encryption/decryption works correctly across providers:
 * - Encrypting with OpenJCEPlus (OpenSSL) and decrypting with SunJCE
 * - Encrypting with SunJCE and decrypting with OpenJCEPlus (OpenSSL)
 *
 * This validates that the OpenSSL implementation is standards-compliant and can
 * interoperate with other JCE providers.
 *
 * Tests are skipped if OpenSSL is not available on the system.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLAES256Interop extends BaseTestAESInterop {

    private static OpenJCEPlus provider;
    private static boolean opensslAvailable = false;

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        setInteropProviderName(Utils.PROVIDER_SunJCE);
        setKeySize(256);

        // Check if OpenSSL is available
        try {
            provider = (OpenJCEPlus) Security.getProvider(Utils.TEST_SUITE_PROVIDER_NAME);
            if (provider == null) {
                provider = new OpenJCEPlus();
                Security.addProvider(provider);
            }

            OpenSSLContext opensslContext = provider.getOpenSSLContext();
            opensslAvailable = (opensslContext != null);
            System.out.println("OpenSSL available for interop tests: " + opensslAvailable);
            if (opensslAvailable) {
                System.out.println("OpenSSL version: " + opensslContext.getOpenSSLVersion());
                System.out.println("OpenSSL path: " + opensslContext.getOpenSSLInstallPath());
            }
        } catch (Exception e) {
            System.out.println("OpenSSL not available for interop tests: " + e.getMessage());
            opensslAvailable = false;
        }
    }

    @BeforeEach
    public void checkOpenSSLAvailable() {
        // Skip all tests if OpenSSL is not available
        assumeTrue(opensslAvailable, "Skipping test - OpenSSL is not available");
    }
}

