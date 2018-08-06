package com.xy.spring.security.oauth2.mock;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Created by xiaoyao9184 on 2018/7/26.
 */
public class AlwaysMatchePasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        return rawPassword.toString();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return true;
    }
}
