package org.itxtech.securesnc;

import org.itxtech.securesnc.util.AcmeUtils;
import org.itxtech.securesnc.util.CSRBuilder;
import org.itxtech.securesnc.util.Logger;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Http01Challenge;

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
    private String user;
    private String pass;
    private String root;
    private boolean test;

    private boolean completed;
    private Proxy proxy;
    private SncClient client;
    private String privateKey;
    private String publicKey;

    public boolean isCompleted() {
        return completed;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public Application(String domain,
                       String address,
                       String user,
                       String pass,
                       String root,
                       boolean test) {
        this.domain = domain;
        this.address = address;
        this.user = user;
        this.pass = pass;
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

        Logger.info("需要申请证书的域名：" + domain);
        Logger.info("使用 Let's Encrypt " + (test ? "测试" : "生产") + " 服务器");
        Session session = new Session(test ? TESTING_SERVER : PRODUCTION_SERVER);
        if (proxy != null) {
            session.setProxy(proxy);
        }
        Logger.info("创建账户并登录");
        Account account = AcmeUtils.createAccountAndLogin(session);
        Logger.info("请求证书");
        Order order = account.newOrder()
                .domains(domains)
                .create();
        client = new SncClient(address, user, pass);
        client.login();
        for (Authorization auth : order.getAuthorizations()) {
            if (auth.getStatus() != Status.VALID) {
                processAuth(auth);
            }
        }

        Logger.info("创建域名密钥对");
        KeyPair domainKeyPair = AcmeUtils.createKeyPair();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(stream);
        AcmeUtils.writeKeyPair(domainKeyPair, writer);
        writer.close();
        privateKey = stream.toString();

        CSRBuilder csrb = new CSRBuilder();
        for (String d : domainList) {
            csrb.addDomain(d);
        }
        csrb.setOrganization("SNCIDC");
        csrb.sign(domainKeyPair);

        Logger.info("完成请求");
        order.execute(csrb.getEncoded());

        while (order.getStatus() != Status.VALID) {
            Thread.sleep(3000L);
            order.update();
        }

        Logger.info("保存证书");
        Certificate cert = order.getCertificate();

        ByteArrayOutputStream pubKey = new ByteArrayOutputStream();
        writer = new OutputStreamWriter(pubKey);
        cert.writeCertificate(writer);
        writer.close();

        publicKey = pubKey.toString();

        uploadCert();
        completed = true;
    }

    private void processAuth(Authorization auth) throws Exception {
        Logger.info("处理域名验证 " + auth.getDomain());
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        String token = challenge.getToken();
        String content = challenge.getAuthorization();
        Logger.info("上传验证文件");

        if (client.uploadFile(root + "/.well-known/acme-challenge", token, content.getBytes())) {
            Logger.info("验证文件已上传");
        } else {
            Logger.error("验证文件上传失败");
            System.exit(-1);
        }
        Logger.info("请求验证");
        challenge.trigger();

        while (auth.getStatus() != Status.VALID) {
            Thread.sleep(3000L);
            auth.update();
        }

        Logger.info("验证完成");
    }

    private void uploadCert() throws Exception{
        Logger.info("上传证书");
        client.uploadCertificate(privateKey, publicKey);
    }
}
