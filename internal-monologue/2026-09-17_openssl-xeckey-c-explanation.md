# 2026-09-17 — OpenSSLXECKey.c line-by-line explanation

## Action
Created HTML artifact documenting every section of
`src/main/native/openssl/OpenSSLXECKey.c` (581 lines).

## Coverage
- File header: XEC/EdDSA scope, CurveUtil.CURVE ordinal table, four key format conventions
- optionToNID helper: ordinal → NID_X25519/NID_X448/NID_ED25519/NID_ED448
- XECKEY_generate: EVP_PKEY_CTX_new_id, keygen_init, EVP_PKEY_keygen, two-call get_raw_public_key → FastJNIBuffer
- XECKEY_createPrivateKey: d2i_PrivateKey(EVP_PKEY_NONE) auto-detection, cleanup-before-NULL-check pattern, FastJNIBuffer write
- XECKEY_createPublicKey: d2i_PUBKEY for SubjectPublicKeyInfo DER
- XECKEY_getPrivateKeyBytes: three-step pattern (size query → NewByteArray → pin + i2d in-place)
- XECKEY_getPublicKeyBytes: same three-step pattern with get_raw_public_key; DeleteLocalRef on error
- XECKEY_delete: EVP_PKEY_free with debug log
- XECKEY_computeECDHSecret: one-shot derive (CTX_new → derive_init → set_peer → derive×2 → commit)
- XDHKeyAgreement_init: staged ECDH, returns EVP_PKEY_CTX* handle
- XDHKeyAgreement_setPeer: sets peer on existing derive context
- Design summary: two ECDH paths, FastJNIBuffer vs Java array table, in-place DER encoding, memory ownership rules
