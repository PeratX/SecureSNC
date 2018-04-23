package org.itxtech.securesnc;

import org.apache.commons.cli.*;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;
import org.itxtech.securesnc.util.Logger;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.List;

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

        Option root = new Option("r", "root", true, "Root of your website, default = /wwwroot");
        options.addOption(root);

        Option test = new Option("t", "test", false, "Enable test mode, this will obtain a fake cert");
        options.addOption(test);

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

    private static final String PRODUCTION_SERVER = "acme://letsencrypt.org";
    private static final String TESTING_SERVER = "acme://letsencrypt.org/staging";

    private static String domain;
    private static String address;
    private static String ftpUser;
    private static String ftpPass;
    private static String root;
    private static boolean test;

    private static void run(CommandLine cmd) throws Exception{
        test = cmd.hasOption("test");
        root = cmd.getOptionValue("root") == null ? "/wwwroot" : cmd.getOptionValue("root");
        domain = cmd.getOptionValue("domain");
        address = cmd.getOptionValue("address");
        ftpUser = cmd.getOptionValue("ftp-user");
        ftpPass = cmd.getOptionValue("ftp-pass");

        String[] domains = domain.split(",");
        List<String> domainList = Arrays.asList(domains);

        Logger.info("Obtaining certificate for " + domain);
        Logger.info("Now using " + (test ? "Let's Encrypt testing server" : "Let's Encrypt production server"));
        Session session = new Session(test ? TESTING_SERVER : PRODUCTION_SERVER);
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
                .domains(domains)
                .create();
        for (Authorization auth : order.getAuthorizations()) {
            if (auth.getStatus() != Status.VALID) {
                processAuth(auth);
            }
        }

        Logger.info("Creating domain key pair");
        KeyPair domainKeyPair = keyPairGenerator.generateKeyPair();
        FileWriter fileWriter = new FileWriter("private.key");
        KeyPairUtils.writeKeyPair(domainKeyPair, fileWriter);
        fileWriter.close();
        Logger.info("Private key saved");

        CSRBuilder csrb = new CSRBuilder();
        for (String d : domainList){
            csrb.addDomain(d);
        }
        csrb.setOrganization("SNCIDC");
        csrb.sign(domainKeyPair);

        Logger.info("Finalizing the order");
        order.execute(csrb.getEncoded());

        while (order.getStatus() != Status.VALID) {
            Thread.sleep(3000L);
            order.update();
        }

        Logger.info("Writing the certificate");
        Certificate cert = order.getCertificate();
        FileWriter crt = new FileWriter("cert.crt");
        cert.writeCertificate(crt);
        crt.close();

        ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
        csrb.write(privateKey);
        ByteArrayOutputStream publicKey = new ByteArrayOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(publicKey);
        cert.writeCertificate(writer);
        writer.close();

        uploadCert(privateKey.toByteArray(), publicKey.toByteArray());

        Logger.info("All done");
    }

    private static void processAuth(Authorization auth) throws Exception{
        Logger.info("Processing authorization for " + auth.getDomain());
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        String token = challenge.getToken();
        String content = challenge.getAuthorization();
        Logger.info("Token: " + token);
        Logger.info("Content: " + content);
        Logger.info("Connecting FTP server");

        FTPClient ftpClient = new FTPClient();
        ftpClient.setControlEncoding("UTF-8");
        ftpClient.connect(address, 21);
        ftpClient.login(ftpUser, ftpPass);
        if (!FTPReply.isPositiveCompletion(ftpClient.getReplyCode())){
            Logger.info("Failed to connect to ftp server: " + address);
            return;
        }
        ftpClient.enterLocalActiveMode();
        ftpClient.changeWorkingDirectory(root);
        ftpClient.makeDirectory(".well-known");
        ftpClient.changeWorkingDirectory(".well-known");
        ftpClient.makeDirectory("acme-challenge");
        ftpClient.changeWorkingDirectory("acme-challenge");
        if (!ftpClient.storeFile(token, new ByteArrayInputStream(content.getBytes()))){
            Logger.info("Failed to upload challenge");
            ftpClient.logout();
            return;
        }
        ftpClient.logout();
        Logger.info("Upload completed");
        Logger.info("Triggering challenge");
        challenge.trigger();

        while (auth.getStatus() != Status.VALID) {
            Thread.sleep(3000L);
            auth.update();
        }

        Logger.info("Challenge completed");
    }

    private static void uploadCert(byte[] privateKey, byte[] publicKey) throws Exception{
        Logger.info("Uploading keys");

        FTPClient ftpClient = new FTPClient();
        ftpClient.setControlEncoding("UTF-8");
        ftpClient.connect(address, 21);
        ftpClient.login(ftpUser, ftpPass);
        if (!FTPReply.isPositiveCompletion(ftpClient.getReplyCode())){
            Logger.info("Failed to connect to ftp server: " + address);
            return;
        }
        ftpClient.enterLocalActiveMode();
        ftpClient.changeWorkingDirectory("/");
        Logger.info("Uploading private key");
        if (!ftpClient.storeFile("ssl.key", new ByteArrayInputStream(privateKey))){
            Logger.info("Failed to upload private key");
            ftpClient.logout();
            return;
        }
        Logger.info("Uploading public key");
        if (!ftpClient.storeFile("ssl.crt", new ByteArrayInputStream(publicKey))){
            Logger.info("Failed to upload public key");
            ftpClient.logout();
            return;
        }
        ftpClient.logout();
    }
}
