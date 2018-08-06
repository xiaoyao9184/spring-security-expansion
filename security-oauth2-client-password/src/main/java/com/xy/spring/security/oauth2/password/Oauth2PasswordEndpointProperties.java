package com.xy.spring.security.oauth2.password;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Created by xiaoyao9184 on 2017/8/8.
 */
@ConfigurationProperties(
        prefix = "security.oauth2.sso"
)
public class Oauth2PasswordEndpointProperties {

    private boolean useSsoLoginPathPrefix = true;
    private String passwordLoginPath = "/password";

    public String getPasswordLoginPath() {
        return passwordLoginPath;
    }

    public void setPasswordLoginPath(String passwordLoginPath) {
        this.passwordLoginPath = passwordLoginPath;
    }

    public boolean isUseSsoLoginPathPrefix() {
        return useSsoLoginPathPrefix;
    }

    public void setUseSsoLoginPathPrefix(boolean useSsoLoginPathPrefix) {
        this.useSsoLoginPathPrefix = useSsoLoginPathPrefix;
    }
}
