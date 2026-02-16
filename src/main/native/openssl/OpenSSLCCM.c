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

#include "OpenSSLCCM.h"
#include "OpenSSLContext.h"
#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLLogging.h"

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1init(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_init";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (tagLen < MIN_CCM_TAG_SIZE || tagLen > MAX_CCM_TAG_SIZE ||
        tagLen % 2 != 0) {
        throwOpenSSLException(
            env, OPENSSL_UNSPECIFIED,
            "Invalid CCM tag length: must be 4-16 bytes and even");
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

    if (ivLen < MIN_CCM_IV_SIZE || ivLen > MAX_CCM_IV_SIZE) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid CCM IV length: must be 7-13 bytes");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    int encryptFlag = (encrypt != 0) ? 1 : 0;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM_init: mode=%s, ivLen=%d, tagLen=%d",
            encryptFlag ? "encrypt" : "decrypt", ivLen, tagLen);
    }
#endif

    if (EVP_CipherInit_ex(ctx, cipherCtx->cipher, NULL, NULL, NULL,
                          encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to initialize CCM cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, ivLen, NULL) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to set CCM IV length");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tagLen, NULL) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to set CCM tag length");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char*)keyBytes,
                          (unsigned char*)ivBytes, encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to set CCM key and IV");
        logOpenSSLError("EVP_CipherInit_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    cipherCtx->tagLen = tagLen;

    cleanupByteArrays(env, key, keyBytes, iv, ivBytes);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL CCM cipher initialized successfully");
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    CCM_update
 * Signature: (JJII[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1update(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_update";

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

    if (cipherCtx == NULL || cipherCtx->ctx == NULL) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    EVP_CIPHER_CTX* ctx = cipherCtx->ctx;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL CCM_update: inputLen=%d, aadLen=%d",
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

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL Processed %d bytes of AAD",
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
                              "Failed to update CCM cipher");
        logOpenSSLError("EVP_CipherUpdate");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_TRUE);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM update: processed %d bytes, output %d "
            "bytes",
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
 * Method:    CCM_encryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_encryptFinal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    EVP_CIPHER_CTX* ctx = cipherCtx->ctx;
    int totalOutLen = 0;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM_encryptFinal: inputLen=%d, tagLen=%d",
            inputLen, tagLen);
    }
#endif

    // For CCM, set plaintext length before processing AAD
    int outLen = 0;

    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, inputLen) != 1) {
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to set CCM plaintext length");
        logOpenSSLError("EVP_CipherUpdate(set plaintext length)");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL Set CCM plaintext length: %d bytes",
                     inputLen);
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

        outLen = 0;

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

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL Processed %d bytes of AAD",
                         aadLen);
        }
#endif
    }

    // Validate output buffer size (ciphertext + tag)
    jsize outputLength       = (*env)->GetArrayLength(env, output);
    int   requiredOutputSize = inputLen + tagLen;

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

    // Process input if present
    if (inputLen > 0) {
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

        outLen = 0;

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

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_CCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                inputLen, outLen);
        }
#endif
    } else {
        // For zero-length plaintext
        outLen              = 0;
        unsigned char dummy = 0;

        if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                             &outLen, &dummy, 0) != 1) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process zero-length plaintext");
            logOpenSSLError("EVP_CipherUpdate(zero-length)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL Processed zero-length plaintext");
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
                              "Failed to finalize CCM cipher");
        logOpenSSLError("EVP_CipherFinal_ex");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    totalOutLen += finalLen;

    // Get the tag and append it to the output
    unsigned char tag[MAX_CCM_TAG_SIZE];

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tagLen, tag) != 1) {
        cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
        throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to get CCM tag");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(GET_TAG)");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

    memcpy(outputBytes + outputOffset + totalOutLen, tag, tagLen);
    totalOutLen += tagLen;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL Appended CCM tag, length: %d, total "
            "output: %d bytes",
            tagLen, totalOutLen);
    }
#endif

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM encrypt final complete, total output: %d bytes",
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
 * Method:    CCM_decryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface_CCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong fipsFlag, jlong cipherId,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_decryptFinal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    CipherContext* cipherCtx = NULL;
    if (!validateCipherContext(env, fipsFlag, cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    EVP_CIPHER_CTX* ctx = cipherCtx->ctx;
    int totalOutLen = 0;

    // Calculate actual ciphertext length (input - tag)
    int actualInputLen = inputLen - tagLen;

    if (actualInputLen < 0) {
        throwOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Input length less than tag length");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM_decryptFinal: inputLen=%d, "
            "actualInputLen=%d, tagLen=%d",
            inputLen, actualInputLen, tagLen);
    }
#endif

    // For CCM, set plaintext length before processing AAD
    int outLen = 0;

    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, actualInputLen) != 1) {
        throwOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to set CCM plaintext length");
        logOpenSSLError("EVP_CipherUpdate(set plaintext length)");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL Set CCM plaintext length: %d bytes",
                     actualInputLen);
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

        outLen = 0;

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

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL Processed %d bytes of AAD",
                         aadLen);
        }
#endif
    }

    // Validate output buffer size (plaintext only)
    jsize outputLength = (*env)->GetArrayLength(env, output);

    if (outputOffset < 0 || actualInputLen < 0 ||
        outputOffset + actualInputLen > outputLength) {
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

    // Extract and set the tag for verification
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

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tagLen, tag) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_FALSE);
            throwOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                                  "Failed to set CCM tag");
            logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_CCM OpenSSL Set CCM tag for verification, length: %d",
                tagLen);
        }
#endif
    }

    // Process ciphertext if present
    if (actualInputLen > 0) {
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

        outLen = 0;

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

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_CCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                actualInputLen, outLen);
        }
#endif
    } else {
        // For zero-length ciphertext
        outLen              = 0;
        unsigned char dummy = 0;

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

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL Processed zero-length ciphertext");
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
                              "CCM tag verification failed");
#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL CCM tag verification failed");
        }
#endif
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return OPENSSL_TAG_MISMATCH_ERROR;
    }

    totalOutLen += finalLen;

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM decrypt final complete, total output: %d bytes",
            totalOutLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return totalOutLen;
}