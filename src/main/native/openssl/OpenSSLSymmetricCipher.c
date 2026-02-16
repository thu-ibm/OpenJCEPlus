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
#include "OpenSSLLogging.h"

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1create(
    JNIEnv* env, jclass cls, jlong fipsFlag, jstring cipherName) {
    static const char* functionName = "OpenSSLNativeInterface.CIPHER_create";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    int isFIPS  = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);

    if (context == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    const char* name = (*env)->GetStringUTFChars(env, cipherName, NULL);

    if (name == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get cipher name");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Creating cipher with name: %s",
                     name);
    }
#endif

    CipherContext* cipherCtx = (CipherContext*)malloc(sizeof(CipherContext));

    if (cipherCtx == NULL) {
        (*env)->ReleaseStringUTFChars(env, cipherName, name);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to allocate memory for cipher context");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    memset(cipherCtx, 0, sizeof(CipherContext));
    cipherCtx->key       = NULL;
    cipherCtx->iv        = NULL;
    cipherCtx->blockSize = 0;
    cipherCtx->tagLen    = 0;

    cipherCtx->ctx = EVP_CIPHER_CTX_new();

    if (cipherCtx->ctx == NULL) {
        free(cipherCtx);
        (*env)->ReleaseStringUTFChars(env, cipherName, name);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to create cipher context");
        logOpenSSLError("EVP_CIPHER_CTX_new");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    cipherCtx->cipher = EVP_CIPHER_fetch(context->libctx, name, NULL);

    if (cipherCtx->cipher == NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
        free(cipherCtx);
        (*env)->ReleaseStringUTFChars(env, cipherName, name);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to fetch cipher");
        logOpenSSLError("EVP_CIPHER_fetch");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    (*env)->ReleaseStringUTFChars(env, cipherName, name);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Created cipher context %p",
                     cipherCtx);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jlong)cipherCtx;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_init
 * Signature: (JJII[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1init(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jint encrypt,
    jint paddingId, jbyteArray key, jbyteArray iv) {
    static const char* functionName = "OpenSSLNativeInterface.CIPHER_init";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return;
    }

    if (cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    cipherCtx->padding   = paddingId;
    cipherCtx->encrypt   = encrypt;
    cipherCtx->blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);

    jbyte* keyBytes = (*env)->GetByteArrayElements(env, key, NULL);

    if (keyBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get key bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);

    if (cipherCtx->key != NULL) {
        memset(cipherCtx->key, 0, cipherCtx->keyLen);
        free(cipherCtx->key);
    }
    cipherCtx->keyLen = keyLen;
    cipherCtx->key    = (unsigned char*)malloc(keyLen);

    if (cipherCtx->key == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to allocate memory for key");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
    memcpy(cipherCtx->key, keyBytes, keyLen);

    jbyte* ivBytes = NULL;
    jsize  ivLen   = 0;

    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        ivLen   = (*env)->GetArrayLength(env, iv);

        if (cipherCtx->iv != NULL) {
            memset(cipherCtx->iv, 0, cipherCtx->ivLen);
            free(cipherCtx->iv);
        }
        cipherCtx->ivLen = ivLen;
        cipherCtx->iv    = (unsigned char*)malloc(ivLen);

        if (cipherCtx->iv == NULL) {
            cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to allocate memory for IV");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return;
        }
        memcpy(cipherCtx->iv, ivBytes, ivLen);
    }

    // Stream cipher modes have block size of 1 and don't need padding 
    if (cipherCtx->blockSize == 1) {
        EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
    } else {
        EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, paddingId != 0);
    }

    int result;

    if (encrypt) {
        result = EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                    (unsigned char*)keyBytes,
                                    ivBytes ? (unsigned char*)ivBytes : NULL);
    } else {
        result = EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                    (unsigned char*)keyBytes,
                                    ivBytes ? (unsigned char*)ivBytes : NULL);
    }

    cleanupByteArrays(env, key, keyBytes, iv, ivBytes);

    if (result != 1) {
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to initialize cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getBlockSize(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_getBlockSize";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    int isFIPS  = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);

    if (context == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL ||
        cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Cipher block size: %d", blockSize);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return blockSize;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getKeyLength(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_getKeyLength";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    int isFIPS  = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);

    if (context == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL ||
        cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int keyLength = EVP_CIPHER_get_key_length(cipherCtx->cipher);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Cipher key length: %d", keyLength);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return keyLength;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1getIVLength(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_getIVLength";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    int isFIPS  = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);

    if (context == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL ||
        cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int ivLength = EVP_CIPHER_get_iv_length(cipherCtx->cipher);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Cipher IV length: %d", ivLength);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return ivLength;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_encryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptUpdate(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_encryptUpdate";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    if (needsReinit) {
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_EncryptInit_ex");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }
    }

    // Total length
    jsize inputLength  = (*env)->GetArrayLength(env, input);
    jsize outputLength = (*env)->GetArrayLength(env, output);

    if (inputOffset < 0 || inputLen < 0 ||
        inputOffset + inputLen > inputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid input parameters");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid output parameters");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* inBytes = (*env)->GetByteArrayElements(env, input, NULL);

    if (inBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get input bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* outBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outBytes == NULL) {
        cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int outLen = 0;

    if (EVP_EncryptUpdate(
            cipherCtx->ctx, (unsigned char*)(outBytes + outputOffset), &outLen,
            (unsigned char*)(inBytes + inputOffset), inputLen) != 1) {
        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to update cipher");
        logOpenSSLError("EVP_EncryptUpdate");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Encrypted %d bytes, output length: %d",
            inputLen, outLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_decryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptUpdate(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_decryptUpdate";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    if (needsReinit) {
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_DecryptInit_ex");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }
    }

    jsize inputLength  = (*env)->GetArrayLength(env, input);
    jsize outputLength = (*env)->GetArrayLength(env, output);

    if (inputOffset < 0 || inputLen < 0 ||
        inputOffset + inputLen > inputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid input parameters");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid output parameters");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* inBytes = (*env)->GetByteArrayElements(env, input, NULL);

    if (inBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get input bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* outBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outBytes == NULL) {
        cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int outLen = 0;

    if (EVP_DecryptUpdate(
            cipherCtx->ctx, (unsigned char*)(outBytes + outputOffset), &outLen,
            (unsigned char*)(inBytes + inputOffset), inputLen) != 1) {
        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to update cipher");
        logOpenSSLError("EVP_DecryptUpdate");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -3;
    }

    cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Decrypted %d bytes, output length: %d",
            inputLen, outLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_encryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1encryptFinal(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_encryptFinal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    if (needsReinit) {
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_EncryptInit_ex");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }
    }

    jsize outputLength = (*env)->GetArrayLength(env, output);

    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid output parameters");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int totalOutLen = 0;

    if (input != NULL && inputLen > 0) {
        jsize inputLength = (*env)->GetArrayLength(env, input);

        if (inputOffset < 0 || inputLen < 0 ||
            inputOffset + inputLen > inputLength) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Invalid input parameters");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        jbyte* inBytes = (*env)->GetByteArrayElements(env, input, NULL);

        if (inBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        jbyte* outBytes = (*env)->GetByteArrayElements(env, output, NULL);

        if (outBytes == NULL) {
            cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get output bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_EncryptUpdate(cipherCtx->ctx,
                              (unsigned char*)(outBytes + outputOffset),
                              &outLen, (unsigned char*)(inBytes + inputOffset),
                              inputLen) != 1) {
            cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to update cipher");
            logOpenSSLError("EVP_EncryptUpdate");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        totalOutLen += outLen;

        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);
    }

    jbyte* outBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int finalOutLen = 0;

    if (EVP_EncryptFinal_ex(
            cipherCtx->ctx,
            (unsigned char*)(outBytes + outputOffset + totalOutLen),
            &finalOutLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to finalize cipher");
        logOpenSSLError("EVP_EncryptFinal_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -2;
    }

    totalOutLen += finalOutLen;

    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Finalized encryption, total output length: "
            "%d",
            totalOutLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return totalOutLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_decryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1decryptFinal(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_decryptFinal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (cipherCtx->cipher == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    if (needsReinit) {
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
        if (EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_DecryptInit_ex");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }
    }

    jsize outputLength = (*env)->GetArrayLength(env, output);

    if (outputOffset < 0 || outputOffset >= outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid output parameters");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int totalOutLen = 0;

    if (input != NULL && inputLen > 0) {
        jsize inputLength = (*env)->GetArrayLength(env, input);

        if (inputOffset < 0 || inputLen < 0 ||
            inputOffset + inputLen > inputLength) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Invalid input parameters");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        jbyte* inBytes = (*env)->GetByteArrayElements(env, input, NULL);

        if (inBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        jbyte* outBytes = (*env)->GetByteArrayElements(env, output, NULL);

        if (outBytes == NULL) {
            cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get output bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_DecryptUpdate(cipherCtx->ctx,
                              (unsigned char*)(outBytes + outputOffset),
                              &outLen, (unsigned char*)(inBytes + inputOffset),
                              inputLen) != 1) {
            cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to update cipher");
            logOpenSSLError("EVP_DecryptUpdate");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -3;
        }

        totalOutLen += outLen;

        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);
    }

    jbyte* outBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int finalOutLen = 0;
    int result      = EVP_DecryptFinal_ex(
        cipherCtx->ctx, (unsigned char*)(outBytes + outputOffset + totalOutLen),
        &finalOutLen);

    if (result != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);

        unsigned long err = ERR_peek_error();

        if (ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) {
            throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                                  "Bad padding");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -5;
        } else {
            throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                                  "Failed to finalize cipher");
            logOpenSSLError("EVP_DecryptFinal_ex");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -4;
        }
    }

    totalOutLen += finalOutLen;

    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Finalized decryption, total output length: "
            "%d",
            totalOutLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return totalOutLen;
}

/* Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CIPHER_1delete(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId) {
    static const char* functionName = "OpenSSLNativeInterface.CIPHER_delete";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    if (cipherCtx->key != NULL) {
        memset(cipherCtx->key, 0, cipherCtx->keyLen);
        free(cipherCtx->key);
    }
    if (cipherCtx->iv != NULL) {
        memset(cipherCtx->iv, 0, cipherCtx->ivLen);
        free(cipherCtx->iv);
    }

    if (cipherCtx->cipher != NULL) {
        EVP_CIPHER_free((EVP_CIPHER*)cipherCtx->cipher);
    }

    if (cipherCtx->ctx != NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
    }

    free(cipherCtx);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Deleted cipher context %p",
                     cipherCtx);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
