/*
 * Copyright IBM Corp. 2026
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
#include <openssl/provider.h>

#include "OpenSSLGCM.h"
#include "OpenSSLContext.h"
#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLLogging.h"

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1init(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_init";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    // Validate tag length
    if (tagLen < MIN_GCM_TAG_SIZE || tagLen > MAX_GCM_TAG_SIZE) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid GCM tag length: must be 4-16 bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return;
    }

    EVP_CIPHER_CTX* ctx = cipherCtx->ctx;

    jbyte* keyBytes = (*env)->GetByteArrayElements(env, key, NULL);

    if (keyBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get key bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    jbyte* ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);

    if (ivBytes == NULL) {
        cleanupByteArrays(env, key, keyBytes, NULL, NULL);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get IV bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    int ivLen = (*env)->GetArrayLength(env, iv);

    if (ivLen < MIN_GCM_IV_SIZE || ivLen > MAX_GCM_IV_SIZE) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid GCM IV length: must be 1-1024 bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    int encryptFlag = (encrypt != 0) ? 1 : 0;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM_init: mode=%s, ivLen=%d, tagLen=%d",
            encryptFlag ? "encrypt" : "decrypt", ivLen, tagLen);
    }
#endif

    if (EVP_CipherInit_ex(ctx, cipherCtx->cipher, NULL, NULL, NULL,
                          encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to initialize GCM cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    // Set IV length if not default (12 bytes)
    if (ivLen != 12) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL) !=
            1) {
            cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
            throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to set GCM IV length");
            logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return;
        }
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char*)keyBytes,
                          (unsigned char*)ivBytes, encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to set GCM key and IV");
        logOpenSSLError("EVP_CipherInit_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    // Store the tag length for validation in GCM_final
    cipherCtx->tagLen = tagLen;

    cleanupByteArrays(env, key, keyBytes, iv, ivBytes);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_GCM OpenSSL GCM cipher initialized successfully");
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_update
 * Signature: (JJII[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1update(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_update";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    int isFIPS  = (fipsFlag != 0);
    OpenSSLContext* context = getOrCreateContext(env, isFIPS);

    if (context == NULL) {
        // Exception already thrown by getOrCreateContext/createContext
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    EVP_CIPHER_CTX* ctx = cipherCtx->ctx;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_GCM OpenSSL GCM_update: inputLen=%d, aadLen=%d",
                     inputLen, aadLen);
    }
#endif

    if (aad != NULL && aadLen > 0) {
        jbyte* aadBytes = (*env)->GetByteArrayElements(env, aad, NULL);

        if (aadBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get AAD bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_CipherUpdate(ctx, NULL, &outLen, (unsigned char*)aadBytes,
                             aadLen) != 1) {
            (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process AAD");
            logOpenSSLError("EVP_CipherUpdate(AAD)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_GCM OpenSSL Processed %d bytes of AAD",
                         aadLen);
        }
#endif
    }

    jsize inputLength = (*env)->GetArrayLength(env, input);

    if (inputOffset < 0 || inputLen < 0 ||
        inputOffset + inputLen > inputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid input offset or length");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* inputBytes = (*env)->GetByteArrayElements(env, input, NULL);

    if (inputBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get input bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jsize outputLength = (*env)->GetArrayLength(env, output);

    // Validate parameters and protect against integer overflow in pointer arithmetic
    if (outputOffset < 0 || inputLen < 0 || outputOffset > outputLength ||
        outputOffset > INT_MAX - inputLen) {
        cleanupIOArrays(env, input, inputBytes, NULL, NULL, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid parameters or integer overflow");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outputBytes == NULL) {
        cleanupIOArrays(env, input, inputBytes, NULL, NULL, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    int outLen = 0;

    if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                         &outLen, (unsigned char*)(inputBytes + inputOffset),
                         inputLen) != 1) {
        cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to update GCM cipher");
        logOpenSSLError("EVP_CipherUpdate");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_TRUE);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM update: processed %d bytes, output %d "
            "bytes",
            inputLen, outLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return outLen;
}

/*============================================================================
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_encryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_encryptFinal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    EVP_CIPHER_CTX* ctx         = cipherCtx->ctx;
    int             totalOutLen = 0;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM_encryptFinal: inputLen=%d, tagLen=%d",
            inputLen, tagLen);
    }
#endif

    // Process AAD if present
    if (aad != NULL && aadLen > 0) {
        jbyte* aadBytes = (*env)->GetByteArrayElements(env, aad, NULL);

        if (aadBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get AAD bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_CipherUpdate(ctx, NULL, &outLen, (unsigned char*)aadBytes,
                             aadLen) != 1) {
            (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process AAD");
            logOpenSSLError("EVP_CipherUpdate(AAD)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_GCM OpenSSL Processed %d bytes of AAD",
                         aadLen);
        }
#endif
    }

    // Validate output buffer size
    jsize outputLength = (*env)->GetArrayLength(env, output);
    int   requiredOutputSize = inputLen + tagLen;

    if (outputOffset < 0 || outputOffset + requiredOutputSize > outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Output buffer too small or invalid offset");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outputBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    // Process final input if present
    if (input != NULL && inputLen > 0) {
        jbyte* inputBytes = (*env)->GetByteArrayElements(env, input, NULL);

        if (inputBytes == NULL) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                             &outLen,
                             (unsigned char*)(inputBytes + inputOffset),
                             inputLen) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process final input");
            logOpenSSLError("EVP_CipherUpdate");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        totalOutLen += outLen;

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_GCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                inputLen, outLen);
        }
#endif
    }

    // Finalize cipher
    int finalLen = 0;

    if (EVP_CipherFinal_ex(
            ctx, (unsigned char*)(outputBytes + outputOffset + totalOutLen),
            &finalLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to finalize GCM cipher");
        logOpenSSLError("EVP_CipherFinal_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    totalOutLen += finalLen;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL Finalized cipher, final output: %d bytes, "
            "total: %d bytes",
            finalLen, totalOutLen);
    }
#endif

    // Get and append authentication tag
    unsigned char tag[MAX_GCM_TAG_SIZE];

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, tag) != 1) {
        cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to get GCM tag");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(GET_TAG)");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    memcpy(outputBytes + outputOffset + totalOutLen, tag, tagLen);
    totalOutLen += tagLen;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL Appended GCM tag, length: %d, total "
            "output: %d bytes",
            tagLen, totalOutLen);
    }
#endif

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM encryptFinal complete, total output: %d bytes",
            totalOutLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return totalOutLen;
}

/*============================================================================
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_decryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_GCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_decryptFinal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    EVP_CIPHER_CTX* ctx         = cipherCtx->ctx;
    int             totalOutLen = 0;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM_decryptFinal: inputLen=%d, tagLen=%d",
            inputLen, tagLen);
    }
#endif

    // Process AAD if present
    if (aad != NULL && aadLen > 0) {
        jbyte* aadBytes = (*env)->GetByteArrayElements(env, aad, NULL);

        if (aadBytes == NULL) {
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get AAD bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_CipherUpdate(ctx, NULL, &outLen, (unsigned char*)aadBytes,
                             aadLen) != 1) {
            (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process AAD");
            logOpenSSLError("EVP_CipherUpdate(AAD)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_GCM OpenSSL Processed %d bytes of AAD",
                         aadLen);
        }
#endif
    }

    // Validate output buffer size (plaintext = ciphertext - tag)
    jsize outputLength = (*env)->GetArrayLength(env, output);
    int   requiredOutputSize = inputLen - tagLen;

    if (outputOffset < 0 || requiredOutputSize < 0 ||
        outputOffset + requiredOutputSize > outputLength) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Output buffer too small or invalid offset");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);

    if (outputBytes == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    // Extract and set authentication tag for verification
    if (input != NULL && inputLen >= tagLen) {
        jbyte* inputBytes = (*env)->GetByteArrayElements(env, input, NULL);

        if (inputBytes == NULL) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes for tag");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        unsigned char* tag =
            (unsigned char*)(inputBytes + inputOffset + inputLen - tagLen);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, tag) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                                  "Failed to set GCM tag");
            logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_GCM OpenSSL Set GCM tag for verification, length: %d",
                tagLen);
        }
#endif
    }

    // Process ciphertext (excluding tag)
    int actualInputLen = inputLen - tagLen;

    if (input != NULL && actualInputLen > 0) {
        jbyte* inputBytes = (*env)->GetByteArrayElements(env, input, NULL);

        if (inputBytes == NULL) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        int outLen = 0;

        if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                             &outLen,
                             (unsigned char*)(inputBytes + inputOffset),
                             actualInputLen) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process final input");
            logOpenSSLError("EVP_CipherUpdate");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        totalOutLen += outLen;

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_GCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                actualInputLen, outLen);
        }
#endif
    } else if (actualInputLen == 0) {
        // Handle zero-length ciphertext
        int           outLen = 0;
        unsigned char dummy  = 0;

        if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                             &outLen, &dummy, 0) != 1) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process zero-length ciphertext");
            logOpenSSLError("EVP_CipherUpdate(zero-length)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_GCM OpenSSL Processed zero-length ciphertext");
        }
#endif
    }

    // Finalize cipher (verifies authentication tag)
    int finalLen = 0;

    if (EVP_CipherFinal_ex(
            ctx, (unsigned char*)(outputBytes + outputOffset + totalOutLen),
            &finalLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        throwOpenSSLException(env, OPENSSL_CIPHER_TAG_MISMATCH,
                              "GCM tag verification failed");
#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_GCM OpenSSL GCM tag verification failed");
        }
#endif
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return OPENSSL_TAG_MISMATCH_ERROR;
    }

    totalOutLen += finalLen;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL Finalized cipher, final output: %d bytes, "
            "total: %d bytes",
            finalLen, totalOutLen);
    }
#endif

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM decryptFinal complete, total output: %d bytes",
            totalOutLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return totalOutLen;
}