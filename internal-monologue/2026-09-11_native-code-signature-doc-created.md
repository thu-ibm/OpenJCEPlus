# Created native-code-signature-algorithms.html

Created docs/native-code-signature-algorithms.html — line-by-line explanations for
OpenSSLSignature.c and OpenSSLRSAPSS.c, following the same style as native-code-explanations.html.

Covers 15 sections:
- Overview and struct layouts (OpenSSLSignatureContext, OpenSSLRSAPSSContext)
- General API: SIGNATURE_create (algorithm parsing, key loading, EVP_DigestSignInit)
- SIGNATURE_update (streaming vs EdDSA buffer accumulation)
- SIGNATURE_sign / verify (one-shot vs streaming final, 3-way verify result)
- SIGNATURE_reset (EVP_MD_CTX_reset + re-init pattern)
- SIGNATURE_setPSSParams (PSS padding, salt length, MGF1 ordering)
- SIGNATURE_delete (ownership rules: mdCtx owns pkeyCtx)
- EdDSA one-shot: SIGNATUREEdDSA_signOneShot / verifyOneShot
- RSA-PSS dedicated API: createContext, signInit/verifyInit, digestUpdate,
  signFinal/verifyFinal, reset/releaseContext
- Key difference: RSAPSS pkey is NOT owned (caller manages)
