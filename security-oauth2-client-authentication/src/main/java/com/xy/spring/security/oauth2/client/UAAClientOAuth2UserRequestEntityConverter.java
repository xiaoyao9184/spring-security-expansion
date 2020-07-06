package com.xy.spring.security.oauth2.client;

import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static com.xy.spring.security.oauth2.client.UAAClientOAuth2UserService.getClientInfoUri;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
public class UAAClientOAuth2UserRequestEntityConverter extends OAuth2UserRequestEntityConverter {

    private Environment environment;

    public UAAClientOAuth2UserRequestEntityConverter(Environment environment) {
        this.environment = environment;
    }


    /**
     * Returns the {@link RequestEntity} used for the UserInfo Request.
     *
     * @param userRequest the user request
     * @return the {@link RequestEntity} used for the UserInfo Request
     */
    @Override
    public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();

        if(AuthorizationGrantType.CLIENT_CREDENTIALS.equals(clientRegistration.getAuthorizationGrantType())){
            return convertClientInfoRequest(userRequest, clientRegistration);
        }else{
            return super.convert(userRequest);
        }
    }

    public RequestEntity<?> convertClientInfoRequest(OAuth2UserRequest userRequest, ClientRegistration clientRegistration) {
        HttpMethod httpMethod = HttpMethod.GET;
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());

        URI uri = UriComponentsBuilder.fromUriString(getClientInfoUri(this.environment, clientRegistration))
                .build()
                .toUri();

        return new RequestEntity<>(headers, httpMethod, uri);
    }

    /**
     * Sets the {@link Environment} used for dynamic find property of the ClientInfoUri
     * from Spring Security OAuth2 Client Provider properties
     *
     * @param environment the {@link Environment} used for find property of the ClientInfoUri
     */
    public final void setEnvironment(Environment environment) {
        Assert.notNull(environment, "environment cannot be null");
        this.environment = environment;
    }

}
