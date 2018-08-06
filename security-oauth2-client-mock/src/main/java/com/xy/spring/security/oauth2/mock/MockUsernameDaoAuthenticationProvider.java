package com.xy.spring.security.oauth2.mock;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;

/**
 * Created by xiaoyao9184 on 2018/3/27.
 */
public class MockUsernameDaoAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    public boolean supports(Class<?> authentication) {
        return (MockUsernameAuthenticationToken.class
                .isAssignableFrom(authentication));
    }
}
