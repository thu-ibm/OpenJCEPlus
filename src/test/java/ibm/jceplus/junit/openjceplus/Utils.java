/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.OpenJCEPlus;

abstract public class Utils extends ibm.jceplus.junit.base.BaseUtils {

    public static final String TEST_SUITE_PROVIDER_NAME = PROVIDER_OpenJCEPlus;

    /** Provider name used by the OpenSSL-backed test provider. */
    public static final String OPENSSL_PROVIDER_NAME = "OpenJCEPlus-OpenSSL";

    /** Config file that wires all AES/Digest services to the OpenSSL backend. */
    private static final String OPENSSL_CONFIG = "./src/test/OpenSSLOnly.config";

    /**
     * Loads (or retrieves) the "OpenJCEPlus-OpenSSL" provider configured via
     * OpenSSLOnly.config. This is the canonical provider for all OpenSSL tests.
     * Also ensures the full OCK-backed "OpenJCEPlus" provider is registered so
     * that tests which interop with the plain "OpenJCEPlus" name still work.
     */
    public static java.security.Provider loadProviderOpenSSL() {
        try {
            java.security.Provider p = java.security.Security.getProvider(OPENSSL_PROVIDER_NAME);
            if (p == null) {
                OpenJCEPlus jce = new OpenJCEPlus();
                p = jce.configure(OPENSSL_CONFIG);
                java.security.Security.insertProviderAt(p, 1);
            }
            return p;
        } catch (Exception e) {
            e.printStackTrace(System.out);
            System.exit(1);
            return null;
        }
    }

    /**
     * @deprecated Use {@link #loadProviderOpenSSL()} instead.
     *             Retained for non-OpenSSL tests that still use the OCK-backed
     *             "OpenJCEPlus" provider loaded via ProviderOpenSSLAttrs.config.
     */
    @Deprecated
    public static java.security.Provider loadProviderTestSuite() {
        try {
            return loadProviderOpenJCEPlus();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            System.exit(1);
            return null;
        }
    }
}

