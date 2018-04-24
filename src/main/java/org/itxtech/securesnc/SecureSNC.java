package org.itxtech.securesnc;

import org.apache.commons.cli.*;
import org.itxtech.securesnc.util.Logger;

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
    public static final String VERSION = "0.1.0-alpha";

    public static void main(String[] args){
        Options options = new Options();
        Option domain = new Option("d", "domain", true, "Domains you want to apply, now only support 1");
        domain.setRequired(true);
        options.addOption(domain);

        Option address = new Option("a", "address", true, "Address to the panel of SNCIDC");
        address.setRequired(true);
        options.addOption(address);

        Option user = new Option("u", "user", true, "Username of control panel and FTP server");
        user.setRequired(true);
        options.addOption(user);

        Option pass = new Option("p", "pass", true, "Password of control panel");
        pass.setRequired(true);
        options.addOption(pass);

        Option root = new Option("r", "root", true, "Root of your website, default = /wwwroot");
        options.addOption(root);

        Option test = new Option("t", "test", false, "Enable test mode, this will obtain a fake cert");
        options.addOption(test);

        Option proxy = new Option("y", "proxy", true, "Apply a proxy, example: socks://127.0.0.1:1080");
        options.addOption(proxy);

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
        Application app = new Application(cmd.getOptionValue("domain"),
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
    }
}
