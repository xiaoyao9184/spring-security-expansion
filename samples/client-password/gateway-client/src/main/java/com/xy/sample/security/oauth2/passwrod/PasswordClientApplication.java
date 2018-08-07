package com.xy.sample.security.oauth2.passwrod;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@SpringBootApplication
public class PasswordClientApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(PasswordClientApplication.class);
        app.run(args);
    }

}
