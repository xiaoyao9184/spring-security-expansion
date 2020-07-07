package com.xy.sample.security.oauth2.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
@SpringBootApplication
public class ImplicitAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(ImplicitAuthenticationApplication.class);
        app.run(args);
    }

}
