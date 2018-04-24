package org.itxtech.securesnc.util;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;

import java.io.IOException;
import java.io.Writer;
import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * SecureSNC
 * <p>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @author PeratX
 */
public class AcmeUtils {
    private static final int DEFAULT_KEY_SIZE = 2048;

    public static Account createAccountAndLogin(Session session) throws Exception {
        return new AccountBuilder()
                .addContact("mailto:ssl@sncidc.com")
                .agreeToTermsOfService()
                .useKeyPair(createKeyPair())
                .createLogin(session).getAccount();
    }

    public static KeyPair createKeyPair(){
        KeyPairGeneratorSpi generator = new KeyPairGeneratorSpi();
        generator.initialize(DEFAULT_KEY_SIZE, new SecureRandom());
        return generator.generateKeyPair();
    }

    public static void writeKeyPair(KeyPair keypair, Writer w) throws IOException {
        try (JcaPEMWriter jw = new JcaPEMWriter(w)) {
            jw.writeObject(keypair);
        }
    }
}
