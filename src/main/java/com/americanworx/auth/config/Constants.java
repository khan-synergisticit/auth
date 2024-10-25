package com.americanworx.auth.config;

import org.springframework.beans.factory.annotation.Value;

public class Constants {
    @Value("${url.auth-client}")
    private static String url;
    public static final String AUTH_CLIENT_URL = url;

}
