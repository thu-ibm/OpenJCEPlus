/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLLogging.h
 * @brief Debug logging infrastructure for OpenSSL native code.
 *
 * This header declares the logging functions used throughout the OpenSSL
 * native implementation. Logging is controlled by the global 'debug' flag
 * and provides detailed tracing of function calls, data flow, and errors.
 *
 * Logging features:
 * - Function entry/exit tracking
 * - Error and informational messages
 * - Hexadecimal data dumps for debugging
 * - Conditional compilation for debug builds
 *
 * The actual logging implementation is provided by the GSKit logging
 * infrastructure, which handles output formatting and destination.
 */

#ifndef _OPENSSL_LOGGING_H
#define _OPENSSL_LOGGING_H

/**
 * Global debug flag.
 * Set to non-zero to enable debug logging.
 * Controlled by system property or environment variable.
 */
extern int debug;

/**
 * Log function entry.
 * Typically called at the start of each JNI function when debug is enabled.
 *
 * @param functionName Name of the function being entered
 * @return Status code (implementation-defined)
 */
int gslogFunctionEntry(const char* functionName);

/**
 * Log an error message.
 * Used for reporting error conditions.
 *
 * @param formatString Printf-style format string
 * @param ... Variable arguments for format string
 * @return Status code (implementation-defined)
 */
int gslogError(const char* formatString, ...);

/**
 * Log an informational message.
 * Used for general debug output.
 *
 * @param formatString Printf-style format string
 * @param ... Variable arguments for format string
 * @return Status code (implementation-defined)
 */
int gslogMessage(const char* formatString, ...);

/**
 * Log a message with a prefix.
 * Similar to gslogMessage but with additional formatting.
 *
 * @param formatString Printf-style format string
 * @param ... Variable arguments for format string
 * @return Status code (implementation-defined)
 */
int gslogMessagePrefix(const char* formatString, ...);

/**
 * Log binary data as hexadecimal.
 * Useful for debugging cryptographic operations by displaying
 * keys, IVs, ciphertext, etc.
 *
 * @param byte Array of bytes to log
 * @param offset Starting offset in the array
 * @param length Number of bytes to log
 * @param spaceAfter Insert space after this many bytes (0 for no spaces)
 * @param newlineAfter Insert newline after this many bytes (0 for no newlines)
 * @param newlinePrefix Prefix string for lines after newline (can be NULL)
 * @return Status code (implementation-defined)
 */
int gslogMessageHex(char byte[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix);

/**
 * Log function exit.
 * Typically called at the end of each JNI function when debug is enabled.
 *
 * @param functionName Name of the function being exited
 * @return Status code (implementation-defined)
 */
int gslogFunctionExit(const char* functionName);

#endif
