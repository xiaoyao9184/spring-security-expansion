package com.xy.spring.security.oauth2.mock;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import({ MockConfiguration.class })
@Configuration
public @interface EnableOAuth2MockGrant {

}
