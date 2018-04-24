package org.itxtech.securesnc;


import okhttp3.*;

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
public class SncClient {
    private String address;
    private String user;
    private String pass;

    private OkHttpClient httpClient = new OkHttpClient.Builder()
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
            .addInterceptor((chain) -> {
                        Request original = chain.request();
                        Request request = original.newBuilder()
                                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
                                .build();
                        return chain.proceed(request);
                    }
            )
            .build();

    public SncClient(String address, String user, String pass) {
        this.address = address;
        this.user = user;
        this.pass = pass;
    }

    public boolean login() throws Exception {
        Request request = new Request.Builder()
                .url("http://" + address + ":3312/vhost/index.php?c=session&a=login")
                .post(new FormBody.Builder().add("username", user).add("passwd", pass).build())
                .build();
        Response response = httpClient.newCall(request).execute();
        return response.isSuccessful();
    }

    public boolean uploadCertificate(String privateKey, String publicKey) throws Exception {
        Request request = new Request.Builder()
                .url("http://" + address + ":3312/vhost/index.php?c=index&a=ssl")
                .post(new FormBody.Builder().add("certificate", publicKey)
                        .add("certificate_key", privateKey).build())
                .header("Referer", "http://" + address + ":3312/vhost/index.php?c=index&a=sslForm")
                .build();
        Response response = httpClient.newCall(request).execute();
        return response.isSuccessful();
    }

    public boolean uploadFile(String path, String filename, byte[] content) throws Exception {
        httpClient.newCall(new Request.Builder()
                .url("http://" + address + ":3312/vhost/index.php?c=index&a=webftp")
                .build()).execute();
        ArrayList<String> dirs = new ArrayList<>(Arrays.asList(path.split("/")));
        dirs.remove(0);
        StringBuilder nowPath = new StringBuilder("/");
        String cd = "http://" + address + ":3312/vhost/index.php?c=webftp&a=cd&file=";
        for (String dir : dirs) {
            httpClient.newCall(new Request.Builder()
                    .url(cd + nowPath.toString())
                    .build()).execute();
            httpClient.newCall(new Request.Builder()
                    .url("http://" + address + ":3312/vhost/index.php?c=webftp&a=mkdir&dir=" + dir)
                    .build()).execute();
            nowPath.append(dir).append("/");
        }
        httpClient.newCall(new Request.Builder()
                .url(cd + nowPath.toString())
                .build()).execute();
        httpClient.newCall(new Request.Builder()
                .url("http://" + address + ":3312/vhost/index.php?c=webftp&a=upsave")
                .post(new MultipartBody.Builder()
                        .setType(MultipartBody.FORM)
                        .addFormDataPart("myfile", filename,
                                RequestBody.create(MediaType.parse("application/octet-stream"), content))
                        .build())
                .build()).execute();
        return true;
    }
}
