package com.xy.sample.security.oauth2.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
@SpringBootApplication
public class ClientAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(ClientAuthenticationApplication.class);
        app.run(args);
    }

}
