package com.americanworx.auth.config;

import org.springframework.beans.factory.annotation.Value;

public class Constants {

    @Value("${AUTH_CLIENT_URL}")
    public static String AUTH_CLIENT_URL;// = "http://192.168.1.76";

}
