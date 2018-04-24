package org.itxtech.securesnc;

import org.apache.commons.cli.*;
import org.itxtech.securesnc.util.Logger;

import java.io.File;
import java.io.FileWriter;
import java.net.InetSocketAddress;
import java.net.Proxy;

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
    public static final String VERSION = "1.0.0";

    public static void main(String[] args){
        Logger.init();
        Logger.info(PROG_NAME + " 版本：" + VERSION);
        Logger.info("本程序遵循 GPLv3 协议开放源代码");
        Logger.info("Copyright (C) 2018 PeratX, iTX Technologies,");
        Logger.info("                   Shenniao Technology Ltd.");

        Options options = new Options();
        Option domain = new Option("d", "domain", true, "需要申请证书的域名，暂不支持多个");
        domain.setRequired(true);
        options.addOption(domain);

        Option address = new Option("a", "address", true, "虚拟主机控制面板的地址");
        address.setRequired(true);
        options.addOption(address);

        Option user = new Option("u", "user", true, "控制面板的用户名");
        user.setRequired(true);
        options.addOption(user);

        Option pass = new Option("p", "pass", true, "控制面板的密码");
        pass.setRequired(true);
        options.addOption(pass);

        Option root = new Option("r", "root", true, "虚拟主机的根目录，默认为 /wwwroot");
        options.addOption(root);

        Option test = new Option("t", "test", false, "启用测试模式，无签发数量限制，但是签发的是无效证书");
        options.addOption(test);

        Option proxy = new Option("y", "proxy", true, "通过代理使用 ACME 协议，如：socks://127.0.0.1:1080" +
                "\n支持 socks v4/v5 和 http 协议的代理");
        options.addOption(proxy);

        Option save = new Option("s", "save", false, "保存公钥和私钥");
        options.addOption(save);

        DefaultParser parser = new DefaultParser();
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

        try {
            run(cmd);
        } catch (Exception e){
            Logger.logException(e);
        }
        Logger.info(SecureSNC.PROG_NAME + " 已完成所有操作");
    }

    private static void run(CommandLine cmd) throws Exception{
        String domain = cmd.getOptionValue("domain");
        Application app = new Application(domain,
                cmd.getOptionValue("address"),
                cmd.getOptionValue("user"),
                cmd.getOptionValue("pass"),
                cmd.getOptionValue("root") == null ? "/wwwroot" : cmd.getOptionValue("root"),
                cmd.hasOption("test"));
        if (cmd.getOptionValue("proxy") != null) {
            String[] proxy = cmd.getOptionValue("proxy").split("://");
            if (proxy.length != 2) {
                Logger.error("Invalid proxy");
            } else {
                Proxy.Type type;
                switch (proxy[0].toLowerCase()) {
                    case "socks":
                        type = Proxy.Type.SOCKS;
                        break;
                    case "http":
                        type = Proxy.Type.HTTP;
                        break;
                    default:
                        type = null;
                }
                if (type == null) {
                    Logger.error("Invalid proxy type: " + proxy[0].toLowerCase());
                } else {
                    String[] addr = proxy[1].split(":");
                    if (addr.length != 2) {
                        Logger.error("Invalid proxy address: " + proxy[1]);
                    } else {
                        app.setProxy(new Proxy(type, new InetSocketAddress(addr[0], Integer.parseInt(addr[1]))));
                    }
                }
            }
        }
        app.run();
        if (cmd.hasOption("save")) {
            File dir = new File(domain);
            if (!dir.exists()) {
                dir.mkdir();
            }
            FileWriter writer = new FileWriter(domain + "/private.key");
            writer.write(app.getPrivateKey());
            writer.close();

            writer = new FileWriter(domain + "/certificate.crt");
            writer.write(app.getPublicKey());
            writer.close();

            Logger.info("证书已保存至 " + dir.getCanonicalPath());
        }
    }
}
