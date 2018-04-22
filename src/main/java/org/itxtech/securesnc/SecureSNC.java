package org.itxtech.securesnc;

import org.apache.commons.cli.*;
import org.itxtech.securesnc.util.Logger;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Http01Challenge;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;

/**
 *
 * SecureSNC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @author PeratX
 *
 */
public class SecureSNC {
    public static final String PROG_NAME = "SecureSNC";
    public static final String VERSION = "0.1.0-alpha";

    public static void main(String[] args){
        Options options = new Options();
        Option domain = new Option("d", "domain", true, "Domains you want to apply, now only support 1");
        domain.setRequired(true);
        options.addOption(domain);

        Option address = new Option("a", "address", true, "Address to the panel of SNCIDC");
        address.setRequired(true);
        options.addOption(address);

        Option fuser = new Option("fu", "ftp-user", true, "Username of FTP server");
        fuser.setRequired(true);
        options.addOption(fuser);

        Option fpass = new Option("fp", "ftp-pass", true, "Password of FTP server");
        fpass.setRequired(true);
        options.addOption(fpass);

        Option user = new Option("u", "user", true, "Username of panel");
        user.setRequired(true);
        options.addOption(user);

        Option pass = new Option("p", "pass", true, "Password of panel");
        pass.setRequired(true);
        options.addOption(pass);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("securesnc", options);
            System.exit(1);
            return;
        }

        Logger.init();
        Logger.info(PROG_NAME + " " + VERSION);

        try {
            run(cmd);
        } catch (Exception e){
            Logger.logException(e);
        }
    }

    private static void run(CommandLine cmd) throws Exception{
        String domain = cmd.getOptionValue("domain");
        String address = cmd.getOptionValue("address");
        String user = cmd.getOptionValue("user");
        String pass = cmd.getOptionValue("pass");
        String ftpUser = cmd.getOptionValue("ftp-user");
        String ftpPass = cmd.getOptionValue("ftp-pass");

        /*String[] domains = domain.split(",");
        List domainList = Arrays.asList(domains);*/

        Logger.info("Obtaining certificate for " + domain);
        Logger.info("Now using Let's Encrypt ACME");
        Session session = new Session("acme://letsencrypt.org");
        //session.setProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", 1080)));
        Logger.info("Creating key pair");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Logger.info("Creating account and logging in");
        Login login = new AccountBuilder()
                .addContact("mailto:ssl@sncidc.com")
                .agreeToTermsOfService()
                .useKeyPair(keyPair)
                .createLogin(session);
        Account account = login.getAccount();
        Logger.info("Ordering certificates");
        Order order = account.newOrder()
                .domains(domain)
                .notAfter(Instant.now().plus(Duration.ofDays(20L)))
                .create();
        for (Authorization auth : order.getAuthorizations()) {
            if (auth.getStatus() != Status.VALID) {
                processAuth(auth);
            }
        }
    }

    private static void processAuth(Authorization auth){
        Logger.info("Processing authorization for " + auth.getDomain());
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        String token = challenge.getToken();
        String content = challenge.getAuthorization();
        Logger.info("Token: " + token);
        Logger.info("Content: " + content);
    }
}
