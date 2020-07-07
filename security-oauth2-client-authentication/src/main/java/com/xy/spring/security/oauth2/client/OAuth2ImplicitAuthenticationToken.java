package com.xy.spring.security.oauth2.client;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.MapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
public class OAuth2ImplicitAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private String access_token;
    private String expires_in;
    private String token_type;
    private String scope;
    private Map<String, Object> additionalParameters = new HashMap<>();
    private ClientRegistration clientRegistration;
    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;

    protected Converter<Map<String, String>, OAuth2AccessTokenResponse> tokenResponseConverter =
            new MapOAuth2AccessTokenResponseConverter();

    public OAuth2ImplicitAuthenticationToken(ClientRegistration clientRegistration,
                                             String access_token,
                                             String expires_in,
                                             String token_type,
                                             String scope,
                                             Map<String, ?> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        Assert.notNull(access_token, "access_token cannot be null");
        Assert.notNull(expires_in, "expires_in cannot be null");
        Assert.notNull(token_type, "token_type cannot be null");
        this.clientRegistration = clientRegistration;
        this.access_token = access_token;
        this.expires_in = expires_in;
        this.token_type = token_type;
        this.scope = scope;
        this.additionalParameters.putAll(additionalParameters);
    }

    public OAuth2ImplicitAuthenticationToken(ClientRegistration clientRegistration,
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
        return this.accessToken != null ?
                this.accessToken.getTokenValue() :
                this.access_token;
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

    /**
     * Returns the additional parameters
     *
     * @return the additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    /**
     * Returns the token response
     *
     * @return OAuth2AccessTokenResponse
     */
    public OAuth2AccessTokenResponse tokenResponse(){
        Map<String, String> mapResponse = this.additionalParameters.entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, kv -> kv.getValue().toString()));

        mapResponse.put(OAuth2ParameterNames.TOKEN_TYPE, this.token_type);
        mapResponse.put(OAuth2ParameterNames.ACCESS_TOKEN, this.access_token);
        mapResponse.put(OAuth2ParameterNames.EXPIRES_IN, this.expires_in);
        mapResponse.put(OAuth2ParameterNames.SCOPE, this.scope);

        return tokenResponseConverter.convert(mapResponse);
    }
}
