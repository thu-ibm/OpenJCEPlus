/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _OPENSSL_LOGGING_H
#define _OPENSSL_LOGGING_H

extern int debug;

int gslogFunctionEntry(const char* functionName);
int gslogError(const char* formatString, ...);
int gslogMessage(const char* formatString, ...);
int gslogMessagePrefix(const char* formatString, ...);
int gslogMessageHex(char byte[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix);
int gslogFunctionExit(const char* functionName);

#endif
