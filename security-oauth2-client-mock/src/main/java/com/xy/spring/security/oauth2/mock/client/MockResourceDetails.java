package com.xy.spring.security.oauth2.mock.client;

import com.xy.spring.security.oauth2.mock.MockTokenGranter;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * Created by xiaoyao9184 on 2018/7/31.
 */
public class MockResourceDetails extends BaseOAuth2ProtectedResourceDetails {

    private String username;

    public MockResourceDetails() {
        setGrantType(MockTokenGranter.GRANT_TYPE);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}
