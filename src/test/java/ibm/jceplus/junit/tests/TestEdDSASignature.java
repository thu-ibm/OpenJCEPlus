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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized EdDSA signature tests for the OpenSSL (and other) backends.
 *
 * Each test is run once per enabled provider (OpenJCEPlus, OpenJCEPlus-OpenSSL, …).
 * The test exercises both Ed25519 and Ed448 sign+verify round-trips using the
 * standard JCA {@link java.security.Signature} API, which drives the
 * {@code SIGNATUREEdDSA_signOneShot} / {@code SIGNATUREEdDSA_verifyOneShot}
 * methods in the native adapter.
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestEdDSASignature extends BaseTestSignature {

    @Parameter(0)
    TestProvider provider;

    private static final byte[] SHORT_MSG  = "a".getBytes();
    private static final byte[] MEDIUM_MSG = "this is the original EdDSA message to be signed".getBytes();
    private static final byte[] LONG_MSG   = ("this is a long EdDSA message used to exercise buffering "
            + "in the one-shot sign/verify path of the OpenSSL EdDSA adapter xxxxxxxxxxxxxxxx"
            + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    // -----------------------------------------------------------------------
    // Ed25519
    // -----------------------------------------------------------------------

    @Test
    public void testEd25519_short() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", getProviderName()).generateKeyPair();
        doSignVerify("Ed25519", SHORT_MSG, kp.getPrivate(), kp.getPublic());
    }

    @Test
    public void testEd25519_medium() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", getProviderName()).generateKeyPair();
        doSignVerify("Ed25519", MEDIUM_MSG, kp.getPrivate(), kp.getPublic());
    }

    @Test
    public void testEd25519_long() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", getProviderName()).generateKeyPair();
        doSignVerify("Ed25519", LONG_MSG, kp.getPrivate(), kp.getPublic());
    }

    // -----------------------------------------------------------------------
    // Ed448
    // -----------------------------------------------------------------------

    @Test
    public void testEd448_short() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed448", getProviderName()).generateKeyPair();
        doSignVerify("Ed448", SHORT_MSG, kp.getPrivate(), kp.getPublic());
    }

    @Test
    public void testEd448_medium() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed448", getProviderName()).generateKeyPair();
        doSignVerify("Ed448", MEDIUM_MSG, kp.getPrivate(), kp.getPublic());
    }

    @Test
    public void testEd448_long() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed448", getProviderName()).generateKeyPair();
        doSignVerify("Ed448", LONG_MSG, kp.getPrivate(), kp.getPublic());
    }

    // -----------------------------------------------------------------------
    // EdDSA (generic algorithm name — provider picks Ed25519 or Ed448)
    // -----------------------------------------------------------------------

    @Test
    public void testEdDSA_medium() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("EdDSA", getProviderName()).generateKeyPair();
        doSignVerify("EdDSA", MEDIUM_MSG, kp.getPrivate(), kp.getPublic());
    }
}
