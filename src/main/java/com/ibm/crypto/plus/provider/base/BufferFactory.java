/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapter;

import java.nio.ByteBuffer;

/**
 * Factory for creating backend-appropriate buffers for cryptographic operations.
 * 
 * This factory creates different buffer types based on the backend:
 * - For OCK backend: Uses FastJNIBuffer (optimized for OCK native calls)
 * - For OpenSSL backend: Uses standard Java ByteBuffer (no OCK dependency)
 * 
 * This allows cipher implementations to work with either backend without
 * requiring OCK libraries when using OpenSSL.
 */
public class BufferFactory {
    
    /**
     * Creates a buffer appropriate for the given backend.
     * 
     * @param backend The native interface backend (OCK or OpenSSL)
     * @param capacity The buffer capacity in bytes
     * @return A CryptoBuffer suitable for the backend
     */
    public static CryptoBuffer createBuffer(NativeInterface backend, int capacity) {
        if (backend instanceof NativeOpenSSLAdapter) {
            // Use standard ByteBuffer for OpenSSL - no OCK dependency
            return new StandardCryptoBuffer(capacity);
        } else {
            // Use FastJNIBuffer for OCK - optimized performance
            return new FastJNICryptoBuffer(capacity);
        }
    }
    
    /**
     * Interface for backend-agnostic buffer operations.
     */
    public interface CryptoBuffer {
        /**
         * Puts bytes into the buffer at the specified index.
         * 
         * @param index Starting index in the buffer
         * @param src Source byte array
         * @param offset Offset in source array
         * @param length Number of bytes to copy
         */
        void put(int index, byte[] src, int offset, int length);
        
        /**
         * Gets bytes from the buffer at the specified index.
         * 
         * @param index Starting index in the buffer
         * @param dst Destination byte array
         * @param offset Offset in destination array
         * @param length Number of bytes to copy
         */
        void get(int index, byte[] dst, int offset, int length);
        
        /**
         * Returns the native pointer for JNI calls.
         * 
         * @return Native memory pointer
         */
        long pointer();
        
        /**
         * Returns the buffer capacity.
         * 
         * @return Capacity in bytes
         */
        int capacity();
    }
    
    /**
     * Standard ByteBuffer-based implementation for OpenSSL backend.
     */
    private static class StandardCryptoBuffer implements CryptoBuffer {
        private final ByteBuffer buffer;
        private final int capacity;
        
        StandardCryptoBuffer(int capacity) {
            this.buffer = ByteBuffer.allocateDirect(capacity);
            this.capacity = capacity;
        }
        
        @Override
        public void put(int index, byte[] src, int offset, int length) {
            if (index + length > capacity) {
                throw new RuntimeException("Buffer index out of bounds: " + 
                    (index + length) + " > " + capacity);
            }
            if (src != null) {
                // Use duplicate to avoid affecting buffer position
                ByteBuffer dup = buffer.duplicate();
                dup.position(index);
                dup.put(src, offset, length);
            }
        }
        
        @Override
        public void get(int index, byte[] dst, int offset, int length) {
            if (index + length > capacity) {
                throw new RuntimeException("Buffer index out of bounds: " + 
                    (index + length) + " > " + capacity);
            }
            if (dst != null) {
                // Use duplicate to avoid affecting buffer position
                ByteBuffer dup = buffer.duplicate();
                dup.position(index);
                dup.get(dst, offset, length);
            }
        }
        
        @Override
        public long pointer() {
            // For OpenSSL, we'll need to get the direct buffer address
            // This will be handled by the OpenSSL adapter
            return 0; // Placeholder - OpenSSL adapter will handle this
        }
        
        @Override
        public int capacity() {
            return capacity;
        }
        
        /**
         * Package-private method to get the underlying ByteBuffer.
         * Used by OpenSSL native adapter.
         */
        ByteBuffer getByteBuffer() {
            return buffer;
        }
    }
    
    /**
     * FastJNIBuffer-based implementation for OCK backend.
     */
    private static class FastJNICryptoBuffer implements CryptoBuffer {
        private final FastJNIBuffer buffer;
        private final int capacity;
        
        FastJNICryptoBuffer(int capacity) {
            this.buffer = FastJNIBuffer.create(capacity);
            this.capacity = capacity;
        }
        
        @Override
        public void put(int index, byte[] src, int offset, int length) {
            buffer.put(index, src, offset, length);
        }
        
        @Override
        public void get(int index, byte[] dst, int offset, int length) {
            buffer.get(index, dst, offset, length);
        }
        
        @Override
        public long pointer() {
            return buffer.pointer();
        }
        
        @Override
        public int capacity() {
            return capacity;
        }
    }
}


