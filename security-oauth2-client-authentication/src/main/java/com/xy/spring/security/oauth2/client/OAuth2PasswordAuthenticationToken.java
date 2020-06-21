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
 * Created by xiaoyao9184 on 2020/6/20.
 */
public class OAuth2PasswordAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private String username;
    private String password;
    private Map<String, Object> additionalParameters = new HashMap<>();
    private ClientRegistration clientRegistration;
    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;

    public OAuth2PasswordAuthenticationToken(ClientRegistration clientRegistration,
                                             String username,
                                             String password) {
        super(Collections.emptyList());
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        Assert.notNull(username, "username cannot be null");
        Assert.notNull(password, "password cannot be null");
        this.clientRegistration = clientRegistration;
        this.username = username;
        this.password = password;
    }

    public OAuth2PasswordAuthenticationToken(ClientRegistration clientRegistration,
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
        return this.username;
    }

    @Override
    public Object getCredentials() {
        return this.password;
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

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }
}
