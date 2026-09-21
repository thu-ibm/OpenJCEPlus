/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parameterized RSA-PSS signature tests for the OpenSSL (and other) backends.
 *
 * Each test is run once per enabled provider.  The tests exercise the native
 * {@code RSAPSS_createContext}/{@code signInit}/{@code digestUpdate}/
 * {@code signFinal}/{@code verifyFinal} chain via the standard JCA
 * {@link Signature} "RSAPSS" / "RSASSA-PSS" algorithm.
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestRSAPSS extends BaseTestSignature {

    @Parameter(0)
    TestProvider provider;

    private static final byte[] SHORT_MSG  = "a".getBytes();
    private static final byte[] MEDIUM_MSG = "this is the original RSAPSS message to be signed".getBytes();
    private static final byte[] LONG_MSG   = ("this is a longer RSAPSS message used to exercise the "
            + "streaming digest-update path in the OpenSSL RSA-PSS adapter "
            + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").getBytes();

    /** The algorithm name used by the provider under test. */
    private String rsaPssAlgo;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        // OpenJCEPlus/OpenSSL uses "RSAPSS"; SunRsaSign uses "RSASSA-PSS"
        String pn = getProviderName();
        if (pn.equalsIgnoreCase("SunRsaSign")) {
            rsaPssAlgo = "RSASSA-PSS";
        } else {
            rsaPssAlgo = "RSAPSS";
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", getProviderName());
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private void doRSAPSS(byte[] msg, PSSParameterSpec spec) throws Exception {
        KeyPair kp = generateRSAKeyPair();

        Signature signing = Signature.getInstance(rsaPssAlgo, getProviderName());
        if (spec != null) signing.setParameter(spec);
        signing.initSign(kp.getPrivate());
        signing.update(msg);
        byte[] sigBytes = signing.sign();

        Signature verifying = Signature.getInstance(rsaPssAlgo, getProviderName());
        if (spec != null) verifying.setParameter(spec);
        verifying.initVerify(kp.getPublic());
        verifying.update(msg);

        assertTrue(verifying.verify(sigBytes), "RSAPSS signature verification failed");
    }

    // -----------------------------------------------------------------------
    // Tests — SHA-256 / MGF1(SHA-256), saltLen=32
    // -----------------------------------------------------------------------

    @Test
    public void testRSAPSS_SHA256_short() throws Exception {
        if (getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")) return; // SHA1 only relevant
        PSSParameterSpec spec = new PSSParameterSpec("SHA256", "MGF1",
                MGF1ParameterSpec.SHA256, 32, 1);
        doRSAPSS(SHORT_MSG, spec);
    }

    @Test
    public void testRSAPSS_SHA256_medium() throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec("SHA256", "MGF1",
                MGF1ParameterSpec.SHA256, 32, 1);
        doRSAPSS(MEDIUM_MSG, spec);
    }

    @Test
    public void testRSAPSS_SHA256_long() throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec("SHA256", "MGF1",
                MGF1ParameterSpec.SHA256, 32, 1);
        doRSAPSS(LONG_MSG, spec);
    }

    // -----------------------------------------------------------------------
    // SHA-384 / MGF1(SHA-384), saltLen=48
    // -----------------------------------------------------------------------

    @Test
    public void testRSAPSS_SHA384_medium() throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec("SHA384", "MGF1",
                MGF1ParameterSpec.SHA384, 48, 1);
        doRSAPSS(MEDIUM_MSG, spec);
    }

    // -----------------------------------------------------------------------
    // SHA-512 / MGF1(SHA-512), saltLen=64
    // -----------------------------------------------------------------------

    @Test
    public void testRSAPSS_SHA512_medium() throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec("SHA512", "MGF1",
                MGF1ParameterSpec.SHA512, 64, 1);
        doRSAPSS(MEDIUM_MSG, spec);
    }

    // -----------------------------------------------------------------------
    // SHA-224 / MGF1(SHA-224), saltLen=28
    // -----------------------------------------------------------------------

    @Test
    public void testRSAPSS_SHA224_medium() throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec("SHA224", "MGF1",
                MGF1ParameterSpec.SHA224, 28, 1);
        doRSAPSS(MEDIUM_MSG, spec);
    }

    // -----------------------------------------------------------------------
    // Default parameters (let the provider choose)
    // -----------------------------------------------------------------------

    @Test
    public void testRSAPSS_defaultParams() throws Exception {
        // No explicit PSS params; provider uses defaults
        doRSAPSS(MEDIUM_MSG, null);
    }
}
