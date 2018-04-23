package org.itxtech.securesnc.util;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.util.KeyPairUtils;

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
    public static Account createAccountAndLogin(Session session) throws Exception {
        return new AccountBuilder()
                .addContact("mailto:ssl@sncidc.com")
                .agreeToTermsOfService()
                .useKeyPair(KeyPairUtils.createKeyPair(2048))
                .createLogin(session).getAccount();
    }
}
