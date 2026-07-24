/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NativeOpenSSLAdapterFIPS extends NativeOpenSSLAdapter {
    private static final boolean printFipsDeveloperModeWarning =
        Boolean.parseBoolean(System.getProperty("openjceplus.fips.devmodewarn", "true"));

    // Use standard System.err for debug output; sun.security.util.Debug is not
    // accessible in all module configurations.
    private static final boolean DEBUG =
        System.getProperty("java.security.debug", "").contains("jceplus");

    private static final boolean isFIPSCertifiedPlatform;
    private static final Map<String, List<String>> supportedPlatforms = new HashMap<>();
    private static final String osName;
    private static final String osArch;

    static {
        supportedPlatforms.put("Arch", List.of("amd64", "ppc64", "s390x", "aarch64"));
        supportedPlatforms.put("OS", List.of("Linux", "AIX", "Windows"));

        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");

        // Check whether the OpenSSL FIPS is supported on this platform
        boolean isOsSupported = false;
        for (String supportedOs : supportedPlatforms.get("OS")) {
            if (osName.contains(supportedOs)) {
                isOsSupported = true;
                break;
            }
        }
        
        boolean isArchSupported = false;
        for (String supportedArch : supportedPlatforms.get("Arch")) {
            if (osArch.contains(supportedArch)) {
                isArchSupported = true;
                break;
            }
        }
        
        isFIPSCertifiedPlatform = isOsSupported && isArchSupported;
    }

    private static volatile NativeOpenSSLAdapterFIPS instance = null;

    private NativeOpenSSLAdapterFIPS(boolean useFIPSMode) {
        super(useFIPSMode);
    }

    /**
     * Gets the singleton instance of the FIPS adapter.
     *
     * Note: FIPS mode validation is performed during instance creation.
     * The adapter will operate in non-FIPS mode on uncertified platforms
     * with appropriate warnings logged.
     *
     * @return the singleton FIPS adapter instance
     */
    public static synchronized NativeOpenSSLAdapterFIPS getInstance() {
        if (instance == null) {
            boolean useFIPSMode = checkFIPSMode();
            instance = new NativeOpenSSLAdapterFIPS(useFIPSMode);
        }

        return instance;
    }

    /**
     * Checks if FIPS mode should be enabled based on platform certification.
     *
     * @return true if platform is FIPS certified, false otherwise
     */
    private static boolean checkFIPSMode() {
        if (!isFIPSCertifiedPlatform) {
            if (printFipsDeveloperModeWarning) {
                System.out.println("WARNING: OpenJCEPlusFIPS with OpenSSL is about to load non FIPS 140-3 library!");
            }
            if (DEBUG) {
                System.err.println("[jceplus] WARNING: OpenJCEPlusFIPS with OpenSSL is about to load non FIPS 140-3 library!");
            }
            return false;
        }
        return true;
    }
}


