package com.xy.spring.security.oauth2.client;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
public class OAuth2ClientCredentialsAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;

    /**
     * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the provided parameters.
     *
     * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
     */
    public OAuth2ClientCredentialsAuthenticationProvider(
            OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient) {

        Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientCredentialsAuthenticationToken passwordAuthenticationToken =
                (OAuth2ClientCredentialsAuthenticationToken) authentication;

        OAuth2AccessTokenResponse accessTokenResponse =
                this.accessTokenResponseClient.getTokenResponse(
                        new OAuth2ClientCredentialsGrantRequest(
                                passwordAuthenticationToken.getClientRegistration()));

        OAuth2ClientCredentialsAuthenticationToken authenticationResult =
                new OAuth2ClientCredentialsAuthenticationToken(
                        passwordAuthenticationToken.getClientRegistration(),
                        accessTokenResponse.getAccessToken(),
                        accessTokenResponse.getRefreshToken(),
                        accessTokenResponse.getAdditionalParameters());
        authenticationResult.setDetails(passwordAuthenticationToken.getDetails());

        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
