# 2026-09-17 — OpenSSLDSAKey.c: added documentation + HTML explanation

## Actions
1. Added full in-source documentation to `src/main/native/openssl/OpenSSLDSAKey.c`:
   - File-level Doxygen comment: handle types, key format table, DSA_ERROR alias,
     deprecation warning, sign/verify path descriptions
   - Block comments on DSA_ERROR constant and all three handle helpers
   - Full Doxygen-style @param/@return on all five static helpers
   - Section-header block comments on all 11 JNI functions
   - Inline explanatory comments inside signDigestCtx, verifyDigestCtx,
     encodeDSA, decodeDSA (cleanup-before-check ordering, get1_ refcount)

2. Created HTML explainer artifact (id: openssl_dsakey_c_explainer) covering
   every section of the file across 18 sections:
   - Includes, DSA_ERROR alias, handle cast helpers
   - encodeDSA / encodeParameters / decodeDSA helpers
   - Both generate overloads, generateParameters
   - createPrivateKey / createPublicKey (one-liner delegates)
   - getParameters, getPrivateKeyBytes, getPublicKeyBytes
   - createPKey: EVP_PKEY_set1_DSA set1_ refcount / dual-handle ownership
   - delete: DSA_free NULL-safety
   - signDigest helper: DSA_size, DSA_sign, actual vs max length
   - signData / verifyData: NONEwithDSA path, NID_undef, dual-array pin cleanup
   - signDigestCtx / verifyDigestCtx: EVP_DigestFinal_ex, get1_ DSA,
     EVP_MD_CTX_get_type (avoids length-to-NID ambiguity)
   - Design summary: two handle types, two sign paths, lifecycle, memory ownership
