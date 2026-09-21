# 2026-09-17 — OpenSSLSignature.c line-by-line explanation

## Action
Created an HTML artifact documenting every section of
`src/main/native/openssl/OpenSSLSignature.c` (1187 lines).

## Coverage
- File header & includes (jni.h, openssl/evp.h, project headers)
- OpenSSLSignatureContext struct (all 10 fields)
- validateSignatureContext helper
- loadKeyFromBytes helper (BIO, d2i_PrivateKey_bio / d2i_PUBKEY_bio)
- signature_create_impl: algorithm parsing, EdDSA buffer init, key load, digest fetch, EVP_DigestSignInit
- SIGNATURE_create JNI entry point
- SIGNATURE_update: EdDSA buffered path vs streaming EVP_DigestSignUpdate
- SIGNATURE_sign: C buffer alloc, EdDSA one-shot vs EVP_DigestSignFinal, Java array creation
- SIGNATURE_verify: tri-state return (1/0/-1), EdDSA vs EVP_DigestVerifyFinal
- SIGNATURE_size, SIGNATURE_reset (EVP_MD_CTX_reset requirement)
- SIGNATURE_setPSSParams: padding, saltLen, MGF1 digest
- SIGNATURE_delete: full resource cleanup order
- SIGNATUREEdDSA_signOneShot and verifyOneShot (alternate direct-key path)
- Design summary: lifecycle flows, two EdDSA paths, memory ownership rules
