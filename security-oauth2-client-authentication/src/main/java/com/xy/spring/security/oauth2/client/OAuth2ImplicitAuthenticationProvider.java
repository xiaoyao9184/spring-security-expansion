package com.xy.spring.security.oauth2.client;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
public class OAuth2ImplicitAuthenticationProvider implements AuthenticationProvider {
    /**
     * Constructs an {@code OAuth2ImplicitAuthenticationProvider} without parameters.
     *
     */
    public OAuth2ImplicitAuthenticationProvider() {
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ImplicitAuthenticationToken implicitAuthenticationToken =
                (OAuth2ImplicitAuthenticationToken) authentication;

        OAuth2AccessTokenResponse accessTokenResponse = implicitAuthenticationToken.tokenResponse();

        OAuth2ImplicitAuthenticationToken authenticationResult =
                new OAuth2ImplicitAuthenticationToken(
                        implicitAuthenticationToken.getClientRegistration(),
                        accessTokenResponse.getAccessToken(),
                        accessTokenResponse.getRefreshToken(),
                        accessTokenResponse.getAdditionalParameters());
        authenticationResult.setDetails(implicitAuthenticationToken.getDetails());

        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ImplicitAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
