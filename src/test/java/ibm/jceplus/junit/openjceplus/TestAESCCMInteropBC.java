/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import ibm.jceplus.junit.base.BaseTestAESCCMInteropBC;
import ibm.jceplus.junit.tests.Tags;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@TestInstance(Lifecycle.PER_CLASS)
public class TestAESCCMInteropBC extends BaseTestAESCCMInteropBC {

    @BeforeAll
    public void beforeAll() throws Exception {
        Utils.loadProviderOpenSSL();
        Utils.loadProviderBC();
        setProviderName(Utils.OPENSSL_PROVIDER_NAME);
        setInteropProviderName(Utils.PROVIDER_BC);
    }
}
