package com.xy.sample.security.oauth2.client;

import com.xy.spring.security.oauth2.client.OAuth2ClientAuthorizedConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${server.error.path:${error.path:/error}}")
    private String errorPath;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(errorPath,"/favicon.ico","/implicit.html");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //noinspection unchecked
        http.apply(new OAuth2ClientAuthorizedConfigurer());
        http.oauth2Client();
        http.oauth2Login();

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
                .csrf().disable()
                .httpBasic();
    }
}
