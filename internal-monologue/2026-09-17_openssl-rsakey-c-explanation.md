# 2026-09-17 — OpenSSLRSAKey.c line-by-line explanation

## Action
Created HTML artifact documenting every section of
`src/main/native/openssl/OpenSSLRSAKey.c` (1271 lines).

## Coverage
- File header: key format conventions, padding/digest ID tables, API split rationale
- mapPadding, mdNameById, setCtxPadding helpers
- RSAKEY_generate: EVP_PKEY_CTX_new_from_name with libctx (review item A-4), BIGNUM exponent
- RSAKEY_createPrivateKey: standard d2i path + inline fallback DER parser for n/d-only keys + non-CRT rebuild
- RSAKEY_createPublicKey: d2i_RSAPublicKey, EVP_PKEY_assign_RSA
- RSAKEY_getPrivateKeyBytes / getPublicKeyBytes: get1_RSA, i2d_*, OPENSSL_free
- RSAKEY_size, RSAKEY_delete
- RSACIPHER_public_encrypt/private_decrypt: OAEP (EVP_PKEY_CTX) vs NoPadding/PKCS1 (RSA_*) split
- RSACIPHER_private_encrypt, public_decrypt: low-level only (NONEwithRSA path)
- digestLenToNid: hash-len → NID mapping and ambiguity note
- RSAKEY_signDataWithRSA / verifyDataWithRSA: RSA_sign/RSA_verify with DigestInfo wrapping
- PKEY_getBaseId: EVP_PKEY type introspection
- RSAKEY_signDigestCtx / verifyDigestCtx: live digest context finalisation + sign
- RSASSL_SIGNATURE_sign / verify: NID_md5_sha1 legacy SSL path
- Design summary: two-tier API table, sign path selection table, memory ownership rules
