package com.xy.spring.security.oauth2.client;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient;

    /**
     * Constructs an {@code OAuth2PasswordAuthenticationProvider} using the provided parameters.
     *
     * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
     */
    public OAuth2PasswordAuthenticationProvider(
            OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient) {

        Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2PasswordAuthenticationToken passwordAuthenticationToken =
                (OAuth2PasswordAuthenticationToken) authentication;

        OAuth2AccessTokenResponse accessTokenResponse =
                this.accessTokenResponseClient.getTokenResponse(
                        new OAuth2PasswordGrantRequest(
                                passwordAuthenticationToken.getClientRegistration(),
                                passwordAuthenticationToken.getUsername(),
                                passwordAuthenticationToken.getPassword()));

        OAuth2PasswordAuthenticationToken authenticationResult =
                new OAuth2PasswordAuthenticationToken(
                        passwordAuthenticationToken.getClientRegistration(),
                        accessTokenResponse.getAccessToken(),
                        accessTokenResponse.getRefreshToken(),
                        accessTokenResponse.getAdditionalParameters());
        authenticationResult.setDetails(passwordAuthenticationToken.getDetails());

        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
