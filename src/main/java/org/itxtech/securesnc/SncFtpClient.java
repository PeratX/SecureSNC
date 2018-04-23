package org.itxtech.securesnc;

import org.apache.commons.net.ftp.FTPClient;
import org.itxtech.securesnc.util.Logger;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;

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
    }

    public boolean connectAndLogin() throws Exception{
        client.connect(address, port);
        boolean result = client.login(user, pass);
        if (result) {
            client.enterLocalPassiveMode();
        }
        return result;
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

    private boolean checkDirectory(String path) throws Exception{
        //path must starts with /
        if (!path.startsWith("/")){
            return false;
        }
        client.changeWorkingDirectory("/");
        if (path.length() > 1) {
            ArrayList<String> dirs = new ArrayList<>(Arrays.asList(path.split("/")));
            dirs.remove(0);
            for (String dir : dirs) {
                client.makeDirectory(dir);
                client.changeWorkingDirectory(dir);
            }
        }
        return true;
    }
}
