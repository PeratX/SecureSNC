package org.itxtech.securesnc.util;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/*
 *  _____            _____            _    _
 * |  __ \          |  __ \          | |  | |
 * | |__) |_ _ _ __ | |  | | ___  ___| | _| |_ ___  _ __
 * |  ___/ _` | '_ \| |  | |/ _ \/ __| |/ / __/ _ \| '_ \
 * | |  | (_| | | | | |__| |  __/\__ \   <| || (_) | |_) |
 * |_|   \__,_|_| |_|_____/ \___||___/_|\_\\__\___/| .__/
 *                                                 | |
 *                                                 |_|
 *
 * This file is a part of PanDesktop.
 * Copyright (C) 2018 pixiv.FUN, All Rights Reserved.
 * Written by PeratX <peratx@itxtech.org>
 *
 */
public class Logger {
    public static final int LOG_LEVEL_INFO = 0;
    public static final int LOG_LEVEL_ERROR = 1;

    private static StringBuffer buffer = null;
    public static int logSizeLimit = 1000;
    private static int verboseLevel = LOG_LEVEL_INFO;

    public static void init() {
        if (buffer != null) {
            buffer.setLength(0);
        } else {
            buffer = new StringBuffer();
        }
    }

    public static void clear() {
        buffer = null;
    }

    public static String getLog() {
        return buffer.toString();
    }

    public static void error(String message) {
        send("[ERROR] " + message, LOG_LEVEL_ERROR);
    }

    public static void info(String message) {
        send("[INFO] " + message, LOG_LEVEL_INFO);
    }

    public static void logException(Throwable e) {
        error(getExceptionMessage(e));
    }

    public static String getExceptionMessage(Throwable e) {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        e.printStackTrace(printWriter);
        return stringWriter.toString();
    }

    private static int getLogSizeLimit() {
        return logSizeLimit;
    }

    private static boolean checkBufferSize() {
        int limit = getLogSizeLimit();
        if (limit == 0) {//DISABLED!
            return false;
        }
        if (limit == -1) {//N0 limit
            return true;
        }
        if (buffer.length() > limit) {//LET's clean it up!
            buffer.setLength(limit);
        }
        return true;
    }

    public static void send(String message, int logLevel) {
        if (logLevel >= verboseLevel) {
            try {
                String fileDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss ").format(new Date());
                message = fileDateFormat + message;
                if (checkBufferSize()) {
                    buffer.insert(0, "\n").insert(0, message);
                }
                System.out.println(message);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
