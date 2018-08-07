package com.xy.sample.security.oauth2.mock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@SpringBootApplication
public class MockClientApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(MockClientApplication.class);
        app.run(args);
    }

}
