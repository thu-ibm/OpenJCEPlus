/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

public final class OpenSSLContext {
    // Constants for OpenSSL configuration
    private static final int VALUE_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OPENSSL_VERSION = 1;
    private static final int VALUE_OPENSSL_INSTALL_PATH = 2;

    // Special marker for unobtained values
    static final String unobtainedValue = new String();

    // Whether to validate OpenSSL was loaded from JRE location
    private static final boolean validateOpenSSLLocation = true;

    // Whether to validate OpenSSL version of load library 
    private static final boolean validateOpenSSLVersion = false;
    
    private long opensslContextId;
    private boolean isFIPS;
    private String opensslVersion = unobtainedValue;
    private String opensslInstallPath = unobtainedValue;

    private static String libraryBuildDate = unobtainedValue;
    
    public static OpenSSLContext createContext(boolean isFIPS) throws OpenSSLException {
        long opensslContextId = OpenSSLNativeInterface.initializeOpenSSL(isFIPS);

        OpenSSLContext context = new OpenSSLContext(opensslContextId, isFIPS);
        
//        if (validateOCKLocation) {
//            OpenSSLNativeInterface.validateLibraryLocation(context);
//        }

        if (validateOpenSSLVersion) {
            OpenSSLNativeInterface.validateLibraryVersion(context);
        }

        return context;
    }
    
    private OpenSSLContext(long opensslContextId, boolean isFIPS) {
        this.opensslContextId = opensslContextId;
        this.isFIPS = isFIPS;
    }
    
    public long getId() {
        return opensslContextId;
    }
    
    public boolean isFIPS() {
        return isFIPS;
    }
    
    public String getOpenSSLVersion() throws OpenSSLException {
        if (opensslVersion == unobtainedValue) {
            obtainOpenSSLVersion();
        }
        return opensslVersion;
    }
    
    public String getOpenSSLInstallPath() throws OpenSSLException {
        if (opensslInstallPath == unobtainedValue) {
            obtainOpenSSLInstallPath();
        }
        return opensslInstallPath;
    }
    
    public static String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            obtainLibraryBuildDate();
        }
        return libraryBuildDate;
    }
    
    private synchronized void obtainOpenSSLVersion() throws OpenSSLException {
        if (opensslVersion == unobtainedValue) {
            opensslVersion = getValue(VALUE_OPENSSL_VERSION);
        }
    }
    
    private synchronized void obtainOpenSSLInstallPath() throws OpenSSLException {
        if (opensslInstallPath == unobtainedValue) {
            opensslInstallPath = getValue(VALUE_OPENSSL_INSTALL_PATH);
        }
    }
    
    private synchronized static void obtainLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = OpenSSLNativeInterface.getLibraryBuildDate();
        }
    }
    
    private String getValue(int valueId) throws OpenSSLException {
        return OpenSSLNativeInterface.CTX_getValue(opensslContextId, valueId);
    }
    
    public String toString() {
        return "OpenSSLContext [isFIPS=" + isFIPS + ", id=" + opensslContextId + "]";
    }
}
