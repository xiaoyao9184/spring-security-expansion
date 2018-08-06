package com.xy.spring.security.oauth2.mock;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Created by xiaoyao9184 on 2017/8/8.
 */
@Configuration
@ConfigurationProperties(
        prefix = "security.oauth2.mock.endpoint"
)
public class MockTokenEndpointProperties {

    public static final String PROPERTIE_ENABLE = "security.oauth2.mock.endpoint.enable";
    public static final String PROPERTIE_ENDPOINT = "/oauth/token/mock";

    private boolean enable = true;
    private String access = "hasAuthority('DEV')";
    private Integer order = Integer.MIN_VALUE;
    private String clientId = "mock";
    private String clientSecret = "mock";

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public Integer getOrder() {
        return order;
    }

    public void setOrder(Integer order) {
        this.order = order;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}
