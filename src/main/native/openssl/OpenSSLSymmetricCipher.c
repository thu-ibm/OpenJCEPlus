/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"

// Helper function to get context
extern OpenSSLContext *getContext(jlong contextId);

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1create
  (JNIEnv *env, jclass cls, jlong contextId, jstring cipherName) {

    logFunctionEntry("CIPHER_create");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_create");
        return -1;
    }
    
    // Get the cipher name
    const char *name = (*env)->GetStringUTFChars(env, cipherName, NULL);
    if (name == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get cipher name");
        logFunctionExit("CIPHER_create");
        return -1;
    }
    
    logMessage("Creating cipher with name: %s", name);
    
    // Create the cipher context
    CipherContext *cipherCtx = (CipherContext *)malloc(sizeof(CipherContext));
    if (cipherCtx == NULL) {
        (*env)->ReleaseStringUTFChars(env, cipherName, name);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to allocate memory for cipher context");
        logFunctionExit("CIPHER_create");
        return -1;
    }
    
    // Initialize the cipher context
    memset(cipherCtx, 0, sizeof(CipherContext));
    cipherCtx->key = NULL;
    cipherCtx->iv = NULL;
    cipherCtx->blockSize = 0;
    
    // Create the EVP cipher context
    cipherCtx->ctx = EVP_CIPHER_CTX_new();
    if (cipherCtx->ctx == NULL) {
        free(cipherCtx);
        (*env)->ReleaseStringUTFChars(env, cipherName, name);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to create cipher context");
        logOpenSSLError("EVP_CIPHER_CTX_new");
        logFunctionExit("CIPHER_create");
        return -1;
    }
    
    // Get the cipher
    cipherCtx->cipher = EVP_CIPHER_fetch(context->libctx, name, NULL);

    if (cipherCtx->cipher == NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
        free(cipherCtx);
        (*env)->ReleaseStringUTFChars(env, cipherName, name);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to fetch cipher");
        logOpenSSLError("EVP_CIPHER_fetch");
        logFunctionExit("CIPHER_create");
        return -1;
    }
    
    // Release the cipher name
    (*env)->ReleaseStringUTFChars(env, cipherName, name);
    
    logMessage("Created cipher context %p", cipherCtx);
    logFunctionExit("CIPHER_create");
    return (jlong)cipherCtx;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_init
 * Signature: (JJII[B[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1init
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jint encrypt, jint paddingId, jbyteArray key, jbyteArray iv) {
    logFunctionEntry("CIPHER_init");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_init");
        return;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_init");
        return;
    }
    
    // Store the padding mode, encrypt flag, and block size
    cipherCtx->padding = paddingId;
    cipherCtx->encrypt = encrypt;
    cipherCtx->blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);
    
    // Get the key
    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get key bytes");
        logFunctionExit("CIPHER_init");
        return;
    }
    
    jsize keyLen = (*env)->GetArrayLength(env, key);
    
    // Store a copy of the key for reinitialization
    if (cipherCtx->key != NULL) {
        memset(cipherCtx->key, 0, cipherCtx->keyLen);  // Clear old key
        free(cipherCtx->key);
    }
    cipherCtx->keyLen = keyLen;
    cipherCtx->key = (unsigned char *)malloc(keyLen);
    if (cipherCtx->key == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to allocate memory for key");
        logFunctionExit("CIPHER_init");
        return;
    }
    memcpy(cipherCtx->key, keyBytes, keyLen);
    
    // Get the IV if provided
    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        ivLen = (*env)->GetArrayLength(env, iv);
        
        // Store a copy of the IV for reinitialization
        if (cipherCtx->iv != NULL) {
            memset(cipherCtx->iv, 0, cipherCtx->ivLen);  // Clear old IV
            free(cipherCtx->iv);
        }
        cipherCtx->ivLen = ivLen;
        cipherCtx->iv = (unsigned char *)malloc(ivLen);
        if (cipherCtx->iv == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to allocate memory for IV");
            logFunctionExit("CIPHER_init");
            return;
        }
        memcpy(cipherCtx->iv, ivBytes, ivLen);
    }
    
    // Set padding - but disable it for stream cipher modes (CFB, OFB, CTR)
    // Stream cipher modes have block size of 1 and don't need padding
    if (cipherCtx->blockSize == 1) {
        // Stream cipher mode - disable padding regardless of paddingId
        EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
    } else {
        // Block cipher mode - use the requested padding
        EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, paddingId != 0);
    }
    
    // Initialize the cipher
    int result;
    if (encrypt) {
        result = EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                   (unsigned char *)keyBytes,
                                   ivBytes ? (unsigned char *)ivBytes : NULL);
    } else {
        result = EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                   (unsigned char *)keyBytes,
                                   ivBytes ? (unsigned char *)ivBytes : NULL);
    }
    
    // Release resources
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    }
    
    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to initialize cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        logFunctionExit("CIPHER_init");
        return;
    }
    
    logFunctionExit("CIPHER_init");
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getBlockSize
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId) {
    logFunctionEntry("CIPHER_getBlockSize");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_getBlockSize");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_getBlockSize");
        return -1;
    }
    
    // Get the block size
    int blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);
    
    logMessage("Cipher block size: %d", blockSize);
    logFunctionExit("CIPHER_getBlockSize");
    return blockSize;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getKeyLength
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId) {
    logFunctionEntry("CIPHER_getKeyLength");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_getKeyLength");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_getKeyLength");
        return -1;
    }
    
    // Get the key length
    int keyLength = EVP_CIPHER_get_key_length(cipherCtx->cipher);
    
    logMessage("Cipher key length: %d", keyLength);
    logFunctionExit("CIPHER_getKeyLength");
    return keyLength;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getIVLength
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId) {
    logFunctionEntry("CIPHER_getIVLength");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_getIVLength");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_getIVLength");
        return -1;
    }
    
    // Get the IV length
    int ivLength = EVP_CIPHER_get_iv_length(cipherCtx->cipher);
    
    logMessage("Cipher IV length: %d", ivLength);
    logFunctionExit("CIPHER_getIVLength");
    return ivLength;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_encryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptUpdate
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit) {
    logFunctionEntry("CIPHER_encryptUpdate");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    // If needsReinit is true, we need to re-initialize the cipher for reuse
    if (needsReinit) {
        // Re-initialize the cipher context with the stored key and IV
        // Disable padding for stream cipher modes (block size = 1)
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                              cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_EncryptInit_ex");
            logFunctionExit("CIPHER_encryptUpdate");
            return -1;
        }
    }
    
    // Check parameters
    jsize inputLength = (*env)->GetArrayLength(env, input);
    jsize outputLength = (*env)->GetArrayLength(env, output);
    
    if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > inputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid input parameters");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid output parameters");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    // Get the input data
    jbyte *inBytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (inBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get input bytes");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    // Get the output buffer
    jbyte *outBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get output bytes");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    // Update the cipher
    int outLen = 0;
    if (EVP_EncryptUpdate(cipherCtx->ctx, (unsigned char *)(outBytes + outputOffset), &outLen,
                         (unsigned char *)(inBytes + inputOffset), inputLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED, "Failed to update cipher");
        logOpenSSLError("EVP_EncryptUpdate");
        logFunctionExit("CIPHER_encryptUpdate");
        return -1;
    }
    
    // Release resources
    (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);
    
    logMessage("Encrypted %d bytes, output length: %d", inputLen, outLen);
    logFunctionExit("CIPHER_encryptUpdate");
    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_decryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptUpdate
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit) {
    logFunctionEntry("CIPHER_decryptUpdate");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_decryptUpdate");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_decryptUpdate");
        return -1;
    }
    
    // If needsReinit is true, we need to re-initialize the cipher for reuse
    if (needsReinit) {
        // Re-initialize the cipher context with the stored key and IV
        // Disable padding for stream cipher modes (block size = 1)
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                              cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_DecryptInit_ex");
            logFunctionExit("CIPHER_decryptUpdate");
            return -1;
        }
    }
    
    // Check parameters
    jsize inputLength = (*env)->GetArrayLength(env, input);
    jsize outputLength = (*env)->GetArrayLength(env, output);
    
    if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > inputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid input parameters");
        logFunctionExit("CIPHER_decryptUpdate");
        return -1;
    }
    
    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid output parameters");
        logFunctionExit("CIPHER_decryptUpdate");
        return -1;
    }
    
    // Get the input data
    jbyte *inBytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (inBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get input bytes");
        logFunctionExit("CIPHER_decryptUpdate");
        return -1;
    }
    
    // Get the output buffer
    jbyte *outBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get output bytes");
        logFunctionExit("CIPHER_decryptUpdate");
        return -1;
    }
    
    // Update the cipher
    int outLen = 0;
    if (EVP_DecryptUpdate(cipherCtx->ctx, (unsigned char *)(outBytes + outputOffset), &outLen,
                         (unsigned char *)(inBytes + inputOffset), inputLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED, "Failed to update cipher");
        logOpenSSLError("EVP_DecryptUpdate");
        logFunctionExit("CIPHER_decryptUpdate");
        return -3;  // Error code for EVP_DecryptUpdate failure
    }
    
    // Release resources
    (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);
    
    logMessage("Decrypted %d bytes, output length: %d", inputLen, outLen);
    logFunctionExit("CIPHER_decryptUpdate");
    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_encryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptFinal
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit) {
    logFunctionEntry("CIPHER_encryptFinal");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_encryptFinal");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_encryptFinal");
        return -1;
    }
    
    // If needsReinit is true, we need to re-initialize the cipher for reuse
    if (needsReinit) {
        // Re-initialize the cipher context with the stored key and IV
        // Disable padding for stream cipher modes (block size = 1)
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                              cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_EncryptInit_ex");
            logFunctionExit("CIPHER_encryptFinal");
            return -1;
        }
    }
    
    // Check parameters
    jsize outputLength = (*env)->GetArrayLength(env, output);
    
    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid output parameters");
        logFunctionExit("CIPHER_encryptFinal");
        return -1;
    }
    
    int totalOutLen = 0;
    
    // Process any remaining input data if provided
    if (input != NULL && inputLen > 0) {
        jsize inputLength = (*env)->GetArrayLength(env, input);
        
        if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > inputLength) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid input parameters");
            logFunctionExit("CIPHER_encryptFinal");
            return -1;
        }
        
        // Get the input data
        jbyte *inBytes = (*env)->GetByteArrayElements(env, input, NULL);
        if (inBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get input bytes");
            logFunctionExit("CIPHER_encryptFinal");
            return -1;
        }
        
        // Get the output buffer
        jbyte *outBytes = (*env)->GetByteArrayElements(env, output, NULL);
        if (outBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get output bytes");
            logFunctionExit("CIPHER_encryptFinal");
            return -1;
        }
        
        // Update the cipher with remaining input
        int outLen = 0;
        if (EVP_EncryptUpdate(cipherCtx->ctx, (unsigned char *)(outBytes + outputOffset), &outLen,
                             (unsigned char *)(inBytes + inputOffset), inputLen) != 1) {
            (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED, "Failed to update cipher");
            logOpenSSLError("EVP_EncryptUpdate");
            logFunctionExit("CIPHER_encryptFinal");
            return -1;
        }
        
        totalOutLen += outLen;
        
        // Release resources
        (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);
    }
    
    // Get the output buffer for final
    jbyte *outBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get output bytes");
        logFunctionExit("CIPHER_encryptFinal");
        return -1;
    }
    
    // Finalize the encryption
    int finalOutLen = 0;
    if (EVP_EncryptFinal_ex(cipherCtx->ctx, (unsigned char *)(outBytes + outputOffset + totalOutLen), &finalOutLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED, "Failed to finalize cipher");
        logOpenSSLError("EVP_EncryptFinal_ex");
        logFunctionExit("CIPHER_encryptFinal");
        return -2;  // Error code for EVP_EncryptFinal failure
    }
    
    totalOutLen += finalOutLen;
    
    // Release resources
    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);
    
    logMessage("Finalized encryption, total output length: %d", totalOutLen);
    logFunctionExit("CIPHER_encryptFinal");
    return totalOutLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_decryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptFinal
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jboolean needsReinit) {
    logFunctionEntry("CIPHER_decryptFinal");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_decryptFinal");
        return -1;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL || cipherCtx->ctx == NULL || cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_decryptFinal");
        return -1;
    }
    
    // If needsReinit is true, we need to re-initialize the cipher for reuse
    if (needsReinit) {
        // Re-initialize the cipher context with the stored key and IV
        // Disable padding for stream cipher modes (block size = 1)
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                              cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED, "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_DecryptInit_ex");
            logFunctionExit("CIPHER_decryptFinal");
            return -1;
        }
    }
    
    // Check parameters
    jsize outputLength = (*env)->GetArrayLength(env, output);
    
    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid output parameters");
        logFunctionExit("CIPHER_decryptFinal");
        return -1;
    }
    
    int totalOutLen = 0;
    
    // Process any remaining input data if provided
    if (input != NULL && inputLen > 0) {
        jsize inputLength = (*env)->GetArrayLength(env, input);
        
        if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > inputLength) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid input parameters");
            logFunctionExit("CIPHER_decryptFinal");
            return -1;
        }
        
        // Get the input data
        jbyte *inBytes = (*env)->GetByteArrayElements(env, input, NULL);
        if (inBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get input bytes");
            logFunctionExit("CIPHER_decryptFinal");
            return -1;
        }
        
        // Get the output buffer
        jbyte *outBytes = (*env)->GetByteArrayElements(env, output, NULL);
        if (outBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get output bytes");
            logFunctionExit("CIPHER_decryptFinal");
            return -1;
        }
        
        // Update the cipher with remaining input
        int outLen = 0;
        if (EVP_DecryptUpdate(cipherCtx->ctx, (unsigned char *)(outBytes + outputOffset), &outLen,
                             (unsigned char *)(inBytes + inputOffset), inputLen) != 1) {
            (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED, "Failed to update cipher");
            logOpenSSLError("EVP_DecryptUpdate");
            logFunctionExit("CIPHER_decryptFinal");
            return -3;  // Error code for EVP_DecryptUpdate failure
        }
        
        totalOutLen += outLen;
        
        // Release resources
        (*env)->ReleaseByteArrayElements(env, input, inBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);
    }
    
    // Get the output buffer for final
    jbyte *outBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Failed to get output bytes");
        logFunctionExit("CIPHER_decryptFinal");
        return -1;
    }
    
    // Finalize the decryption
    int finalOutLen = 0;
    int result = EVP_DecryptFinal_ex(cipherCtx->ctx, (unsigned char *)(outBytes + outputOffset + totalOutLen), &finalOutLen);
    
    if (result != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
        
        // Check if this is a padding error
        unsigned long err = ERR_peek_error();
        if (ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) {
            throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED, "Bad padding");
            logFunctionExit("CIPHER_decryptFinal");
            return -5;  // Error code for bad padding
        } else {
            throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED, "Failed to finalize cipher");
            logOpenSSLError("EVP_DecryptFinal_ex");
            logFunctionExit("CIPHER_decryptFinal");
            return -4;  // Error code for EVP_DecryptFinal failure
        }
    }
    
    totalOutLen += finalOutLen;
    
    // Release resources
    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);
    
    logMessage("Finalized decryption, total output length: %d", totalOutLen);
    logFunctionExit("CIPHER_decryptFinal");
    return totalOutLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1delete
  (JNIEnv *env, jclass cls, jlong contextId, jlong cipherId) {
    logFunctionEntry("CIPHER_delete");
    
    // Get the context
    OpenSSLContext *context = getContext(contextId);
    if (context == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid OpenSSL context ID");
        logFunctionExit("CIPHER_delete");
        return;
    }
    
    // Get the cipher context
    CipherContext *cipherCtx = (CipherContext *)cipherId;
    if (cipherCtx == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid cipher context ID");
        logFunctionExit("CIPHER_delete");
        return;
    }
    
    // Free the stored key and IV
    if (cipherCtx->key != NULL) {
        memset(cipherCtx->key, 0, cipherCtx->keyLen);  // Clear sensitive data
        free(cipherCtx->key);
    }
    if (cipherCtx->iv != NULL) {
        memset(cipherCtx->iv, 0, cipherCtx->ivLen);  // Clear sensitive data
        free(cipherCtx->iv);
    }
    
    // Free the cipher
    if (cipherCtx->cipher != NULL) {
        EVP_CIPHER_free((EVP_CIPHER *)cipherCtx->cipher);
    }
    
    // Free the cipher context
    if (cipherCtx->ctx != NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
    }
    
    // Free the structure
    free(cipherCtx);
    
    logMessage("Deleted cipher context %p", cipherCtx);
    logFunctionExit("CIPHER_delete");
}

