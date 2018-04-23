package org.itxtech.securesnc.util;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.util.KeyPairUtils;

/**
 * @author Administrator
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
