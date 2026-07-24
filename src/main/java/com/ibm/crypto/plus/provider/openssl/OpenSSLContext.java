/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

public final class OpenSSLContext {

    private long opensslContextId;
    private boolean isFIPS;

    public static OpenSSLContext createContext(long opensslContextId, boolean isFIPS) throws OpenSSLException {

        return new OpenSSLContext(opensslContextId, isFIPS);
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

    public String toString() {
        return "OpenSSLContext [isFIPS=" + isFIPS + ", id=" + opensslContextId + "]";
    }
}


