package com.xy.sample.security.oauth2.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
@SpringBootApplication
public class PasswordAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(PasswordAuthenticationApplication.class);
        app.run(args);
    }

}
