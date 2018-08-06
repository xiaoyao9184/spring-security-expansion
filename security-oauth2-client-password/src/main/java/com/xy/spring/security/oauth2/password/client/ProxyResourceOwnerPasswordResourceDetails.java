package com.xy.spring.security.oauth2.password.client;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * Created by xiaoyao9184 on 2018/7/31.
 */
public class ProxyResourceOwnerPasswordResourceDetails extends BaseOAuth2ProtectedResourceDetails {

    public ProxyResourceOwnerPasswordResourceDetails() {
        setGrantType("password");
    }
}

