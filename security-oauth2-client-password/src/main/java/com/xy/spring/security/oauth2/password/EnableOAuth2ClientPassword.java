package com.xy.spring.security.oauth2.password;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
@EnableConfigurationProperties(Oauth2PasswordEndpointProperties.class)
@Import({ OAuth2ClientPasswordConfiguration.class })
@Configuration
public @interface EnableOAuth2ClientPassword {

}
