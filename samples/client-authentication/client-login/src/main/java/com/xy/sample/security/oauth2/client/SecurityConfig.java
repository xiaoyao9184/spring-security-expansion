package com.xy.sample.security.oauth2.client;

import com.xy.spring.security.oauth2.client.OAuth2ClientAuthorizedConfigurer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${server.error.path:${error.path:/error}}")
    private String errorPath;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(errorPath,"/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //noinspection unchecked
        http.apply(new OAuth2ClientAuthorizedConfigurer()
                .authorizationEndpoint()
                    .clientAnonymous()
                    .and()
                .userInfoEndpoint()
                    .useUAAClientInfo()
                    .and());
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



    @Configuration
    public static class GlobalUserConfig {
        private static final String NOOP_PASSWORD_PREFIX = "{noop}";

        private static final Pattern PASSWORD_ALGORITHM_PATTERN = Pattern.compile("^\\{.+}.*$");

        private static final Log logger = LogFactory.getLog(GlobalUserConfig.class);

        @Bean
        @Lazy
        public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
                                                                     ObjectProvider<PasswordEncoder> passwordEncoder) {
            SecurityProperties.User user = properties.getUser();
            List<String> roles = user.getRoles();
            return new InMemoryUserDetailsManager(
                    User.withUsername(user.getName()).password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
                            .roles(StringUtils.toStringArray(roles)).build());
        }

        private String getOrDeducePassword(SecurityProperties.User user, PasswordEncoder encoder) {
            String password = user.getPassword();
            if (user.isPasswordGenerated()) {
                logger.info(String.format("%n%nUsing generated security password: %s%n", user.getPassword()));
            }
            if (encoder != null || PASSWORD_ALGORITHM_PATTERN.matcher(password).matches()) {
                return password;
            }
            return NOOP_PASSWORD_PREFIX + password;
        }
    }

}
