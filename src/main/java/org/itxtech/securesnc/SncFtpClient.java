package org.itxtech.securesnc;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;
import org.itxtech.securesnc.util.Logger;

import java.io.InputStream;
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
public class SncFtpClient {
    private String address;
    private int port;
    private String user;
    private String pass;
    private FTPClient client;

    public SncFtpClient(String address, int port, String user, String pass){
        this.address = address;
        this.user = user;
        this.pass = pass;
        this.port = port;
        client = new FTPClient();
        client.setControlEncoding("UTF-8");
        client.enterLocalPassiveMode();
    }

    public boolean connectAndLogin() throws Exception{
        client.connect(address, port);
        return client.login(user, pass);
    }

    public boolean upload(String remotePath, String filename, InputStream stream){
        try {
            if (!connectAndLogin()){
                Logger.info("Failed to login FTP server: " + address + ":" + String.valueOf(port));
                return false;
            }
            boolean result = uploadFile(remotePath, filename, stream);
            client.logout();
            return result;
        } catch (Exception e){
            Logger.logException(e);
            try{
                client.logout();
            } catch (Exception ignored){}
        }
        return false;
    }

    public boolean uploadFile(String remotePath, String filename, InputStream stream) throws Exception{
        if (checkDirectory(remotePath)) {
            return client.storeFile(filename, stream);
        }
        return false;
    }

    public FTPClient getClient() {
        return client;
    }

    private boolean checkDirectory(String path) throws Exception{
        //path must starts with /
        if (!path.startsWith("/")){
            return false;
        }
        client.changeWorkingDirectory("/");
        if (path.length() > 1) {
            List<String> dirs = Arrays.asList(path.split("/"));
            for (String dir : dirs) {
                client.makeDirectory(dir);
                client.changeWorkingDirectory(dir);
            }
        }
        return true;
    }
}
