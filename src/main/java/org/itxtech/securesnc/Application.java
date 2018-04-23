package org.itxtech.securesnc;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;
import org.itxtech.securesnc.util.AcmeUtils;
import org.itxtech.securesnc.util.Logger;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.net.Proxy;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

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
public class Application {
    private static final String PRODUCTION_SERVER = "acme://letsencrypt.org";
    private static final String TESTING_SERVER = "acme://letsencrypt.org/staging";

    private String domain;
    private String address;
    private String ftpUser;
    private String ftpPass;
    private String root;
    private boolean test;

    private boolean completed;

    private byte[] privateKey;
    private byte[] publicKey;

    private Proxy proxy;

    public boolean isCompleted() {
        return completed;
    }

    public Application(String domain,
                       String address,
                       String ftpUser,
                       String ftpPass,
                       String root,
                       boolean test) {
        this.domain = domain;
        this.address = address;
        this.ftpUser = ftpUser;
        this.ftpPass = ftpPass;
        this.root = root;
        this.test = test;

        this.completed = false;
        this.proxy = null;
    }

    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    public void run() throws Exception {
        String[] domains = domain.split(",");
        List<String> domainList = Arrays.asList(domains);

        Logger.info("Obtaining certificate for " + domain);
        Logger.info("Now using " + (test ? "Let's Encrypt testing server" : "Let's Encrypt production server"));
        Session session = new Session(test ? TESTING_SERVER : PRODUCTION_SERVER);
        if (proxy != null) {
            session.setProxy(proxy);
        }
        Logger.info("Creating account and logging in");
        Account account = AcmeUtils.createAccountAndLogin(session);
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
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);

        CSRBuilder csrb = new CSRBuilder();
        for (String d : domainList) {
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

        ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
        csrb.write(privateKey);
        ByteArrayOutputStream publicKey = new ByteArrayOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(publicKey);
        cert.writeCertificate(writer);
        writer.close();

        this.privateKey = privateKey.toByteArray();
        this.publicKey = publicKey.toByteArray();

        uploadCert(this.privateKey, this.publicKey);

        Logger.info(SecureSNC.PROG_NAME + " done");
    }

    private void processAuth(Authorization auth) throws Exception {
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
        if (!FTPReply.isPositiveCompletion(ftpClient.getReplyCode())) {
            Logger.info("Failed to connect to ftp server: " + address);
            return;
        }
        ftpClient.enterLocalActiveMode();
        ftpClient.changeWorkingDirectory(root);
        ftpClient.makeDirectory(".well-known");
        ftpClient.changeWorkingDirectory(".well-known");
        ftpClient.makeDirectory("acme-challenge");
        ftpClient.changeWorkingDirectory("acme-challenge");
        if (!ftpClient.storeFile(token, new ByteArrayInputStream(content.getBytes()))) {
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

    private void uploadCert(byte[] privateKey, byte[] publicKey) throws Exception {
        Logger.info("Uploading keys");

        FTPClient ftpClient = new FTPClient();
        ftpClient.setControlEncoding("UTF-8");
        ftpClient.connect(address, 21);
        ftpClient.login(ftpUser, ftpPass);
        if (!FTPReply.isPositiveCompletion(ftpClient.getReplyCode())) {
            Logger.info("Failed to connect to ftp server: " + address);
            return;
        }
        ftpClient.enterLocalActiveMode();
        ftpClient.changeWorkingDirectory("/");
        Logger.info("Uploading private key");
        if (!ftpClient.storeFile("ssl.key", new ByteArrayInputStream(privateKey))) {
            Logger.info("Failed to upload private key");
            ftpClient.logout();
            return;
        }
        Logger.info("Uploading public key");
        if (!ftpClient.storeFile("ssl.crt", new ByteArrayInputStream(publicKey))) {
            Logger.info("Failed to upload public key");
            ftpClient.logout();
            return;
        }
        ftpClient.logout();
    }
}
