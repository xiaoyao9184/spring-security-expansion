package com.xy.spring.security.oauth2.client;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
public class OAuth2ClientAuthorizedResolver {
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final AntPathRequestMatcher authorizationRequestMatcher;

    public OAuth2ClientAuthorizedResolver(ClientRegistrationRepository clientRegistrationRepository,
                                          OAuth2AuthorizedClientRepository authorizedClientRepository,
                                          String authorizationRequestBaseUri){
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    }


    public OAuth2AuthorizedClient resolve(HttpServletRequest request){
        String registrationId = this.resolveRegistrationId(request);
        return resolve(request, registrationId);
    }

    public String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher
                    .matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }

    private OAuth2AuthorizedClient resolve(HttpServletRequest request, String registrationId) {
        if (registrationId == null) {
            return null;
        }

        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
        }

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();

        return this.authorizedClientRepository.loadAuthorizedClient(registrationId,currentAuthentication,request);

    }


}
