package com.xy.spring.security.oauth2.mock;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * Created by xiaoyao9184 on 2018/3/27.
 */
public class MockUsernameAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public MockUsernameAuthenticationToken(Object principal) {
        super(principal, "mock");
    }

}
