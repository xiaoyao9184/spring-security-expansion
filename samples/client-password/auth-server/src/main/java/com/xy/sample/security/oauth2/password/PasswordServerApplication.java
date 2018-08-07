package com.xy.sample.security.oauth2.password;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@SpringBootApplication
public class PasswordServerApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(PasswordServerApplication.class);
        app.run(args);
    }

}
