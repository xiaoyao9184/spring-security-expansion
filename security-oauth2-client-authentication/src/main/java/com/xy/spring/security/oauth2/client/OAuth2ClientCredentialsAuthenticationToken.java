package com.xy.spring.security.oauth2.client;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
public class OAuth2ClientCredentialsAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private Map<String, Object> additionalParameters = new HashMap<>();
    private ClientRegistration clientRegistration;
    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;

    public OAuth2ClientCredentialsAuthenticationToken(ClientRegistration clientRegistration) {
        super(Collections.emptyList());
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        this.clientRegistration = clientRegistration;
    }

    public OAuth2ClientCredentialsAuthenticationToken(ClientRegistration clientRegistration,
                                                      OAuth2AccessToken accessToken,
                                                      OAuth2RefreshToken refreshToken,
                                                      Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(accessToken, "accessToken cannot be null");
        this.setAuthenticated(true);
        this.clientRegistration = clientRegistration;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.additionalParameters.putAll(additionalParameters);
    }

    @Override
    public Object getPrincipal() {
        return this.clientRegistration.getClientId();
    }

    @Override
    public Object getCredentials() {
        return this.clientRegistration.getClientSecret();
    }

    /**
     * Returns the {@link ClientRegistration client registration}.
     *
     * @return the {@link ClientRegistration}
     */
    public ClientRegistration getClientRegistration() {
        return this.clientRegistration;
    }

    /**
     * Returns the {@link OAuth2AccessToken access token}.
     *
     * @return the {@link OAuth2AccessToken}
     */
    public OAuth2AccessToken getAccessToken() {
        return this.accessToken;
    }

    /**
     * Returns the {@link OAuth2RefreshToken refresh token}.
     *
     * @return the {@link OAuth2RefreshToken}
     */
    public @Nullable
    OAuth2RefreshToken getRefreshToken() {
        return this.refreshToken;
    }

}
