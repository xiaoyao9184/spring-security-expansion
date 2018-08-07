package com.xy.sample.security.oauth2.passwrod;

import com.xy.spring.security.oauth2.password.EnableOAuth2ClientPassword;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@Configuration
@EnableOAuth2Sso
@EnableOAuth2ClientPassword
public class OAuth2SsoConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .requestMatchers()
                    .anyRequest()
                    .and()
                .authorizeRequests()
                    .anyRequest().fullyAuthenticated()
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    .and()
                .csrf().disable();
    }
}
