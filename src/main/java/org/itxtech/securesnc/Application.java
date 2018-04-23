package org.itxtech.securesnc;

import okhttp3.*;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

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

    private static final OkHttpClient HTTP_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .cookieJar(new CookieJar() {
                private HashMap<String, List<Cookie>> map = new HashMap<>();

                @Override
                public void saveFromResponse(HttpUrl httpUrl, List<Cookie> list) {
                    map.put(httpUrl.host(), list);
                }

                @Override
                public List<Cookie> loadForRequest(HttpUrl httpUrl) {
                    List<Cookie> cookies = map.get(httpUrl.host());
                    return cookies != null ? cookies : new ArrayList<>();
                }
            })
            .addInterceptor((chain) ->{
                        Request original = chain.request();
                        Request request = original.newBuilder()
                                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
                                .build();
                        return chain.proceed(request);
                    }
            )
            .build();

    private String domain;
    private String address;
    private String user;
    private String pass;
    private String ftpPass;
    private String root;
    private boolean test;

    private boolean completed;
    private Proxy proxy;
    private SncFtpClient client;
    private byte[] privateKey;
    private byte[] publicKey;

    public boolean isCompleted() {
        return completed;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public Application(String domain,
                       String address,
                       String user,
                       String pass,
                       String ftpPass,
                       String root,
                       boolean test) {
        this.domain = domain;
        this.address = address;
        this.user = user;
        this.pass = pass;
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
        client = new SncFtpClient(address, 21, user, ftpPass);
        for (Authorization auth : order.getAuthorizations()) {
            if (auth.getStatus() != Status.VALID) {
                processAuth(auth);
            }
        }

        Logger.info("Creating domain key pair");
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(stream);
        KeyPairUtils.writeKeyPair(domainKeyPair, writer);
        writer.close();
        privateKey = stream.toByteArray();

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

        ByteArrayOutputStream pubKey = new ByteArrayOutputStream();
        writer = new OutputStreamWriter(pubKey);
        cert.writeCertificate(writer);
        writer.close();

        publicKey = pubKey.toByteArray();

        uploadCert();

        Logger.info(SecureSNC.PROG_NAME + " done");
        completed = true;
    }

    private void processAuth(Authorization auth) throws Exception {
        Logger.info("Processing authorization for " + auth.getDomain());
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        String token = challenge.getToken();
        String content = challenge.getAuthorization();
        Logger.info("Token: " + token);
        Logger.info("Content: " + content);
        Logger.info("Uploading challenge");

        if (client.upload(root + "/.well-known/acme-challenge", token, new ByteArrayInputStream(content.getBytes()))){
            Logger.info("Challenge upload successfully");
        } else {
            Logger.error("Challenge upload failed");
            System.exit(-1);
        }
        Logger.info("Triggering challenge");
        challenge.trigger();

        while (auth.getStatus() != Status.VALID) {
            Thread.sleep(3000L);
            auth.update();
        }

        Logger.info("Challenge completed");
    }

    private void uploadCert() throws Exception{
        Logger.info("Uploading keys");
        Request request = new Request.Builder()
                .url("http://" + address + ":3312/vhost/index.php?c=session&a=login")
                .post(new FormBody.Builder().add("username", user).add("passwd", pass).build())
                .build();
        Response response = HTTP_CLIENT.newCall(request).execute();
        if (response.isSuccessful()){
            Logger.info("Login successfully");
            request = new Request.Builder()
                    .url("http://" + address + ":3312/vhost/index.php?c=index&a=ssl")
                    .post(new FormBody.Builder().add("certificate", new String(publicKey))
                            .add("certificate_key", new String(privateKey)).build())
                    .header("Referer", "http://" + address + ":3312/vhost/index.php?c=index&a=sslForm")
                    .build();
            response = HTTP_CLIENT.newCall(request).execute();
            if (response.isSuccessful()){
                Logger.info("Certificate uploaded successfully");
            }
        }

        /*if (client.connectAndLogin()){
            if (client.uploadFile("/", "ssl.key", new ByteArrayInputStream(privateKey))){
                Logger.info("Private key has been uploaded successfully");
            } else {
                Logger.error("Private key upload failed");
            }
            if (client.uploadFile("/", "ssl.crt", new ByteArrayInputStream(publicKey))){
                Logger.info("Public key has been uploaded successfully");
            } else {
                Logger.error("Public key upload failed");
            }
            client.getClient().logout();
        } else {
            Logger.error("Upload failed");
        }*/
    }
}
