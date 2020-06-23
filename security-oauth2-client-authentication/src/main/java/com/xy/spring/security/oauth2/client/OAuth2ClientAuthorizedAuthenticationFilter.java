package com.xy.spring.security.oauth2.client;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Collections;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
public class OAuth2ClientAuthorizedAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    /**
     * The default {@code URI} where this {@code Filter} resolve client registration requests.
     */
    public static final String DEFAULT_RESOLVER_PROCESSES_URI = "/login/oauth2/client";
    /**
     * The default {@code URI} where this {@code Filter} processes authentication requests.
     */
    public static final String DEFAULT_FILTER_PROCESSES_URI = DEFAULT_RESOLVER_PROCESSES_URI + "/*";
    public static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

    private OAuth2ClientAuthorizedResolver oAuth2ClientAuthorizedResolver;
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
    private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

    private OAuth2ErrorRefererRequestMatcher oAuth2ErrorRefererRequestMatcher = new OAuth2ErrorRefererRequestMatcher(
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                    + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    private OAuth2ErrorResolver oAuth2ErrorResolver = new OAuth2ErrorResolver();

    /**
     * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizedClientService the authorized client service
     */
    public OAuth2ClientAuthorizedAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                      OAuth2AuthorizedClientService authorizedClientService,
                                                      OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
        this(clientRegistrationRepository, authorizedClientService, userService, DEFAULT_FILTER_PROCESSES_URI);
    }

    /**
     * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizedClientService the authorized client service
     * @param filterProcessesUrl the {@code URI} where this {@code Filter} will process the authentication requests
     */
    public OAuth2ClientAuthorizedAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                      OAuth2AuthorizedClientService authorizedClientService,
                                                      OAuth2UserService<OAuth2UserRequest, OAuth2User> userService,
                                                      String filterProcessesUrl) {
        this(clientRegistrationRepository,
                new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService),
                userService,
                filterProcessesUrl);
    }

    /**
     * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided parameters.
     *
     * @since 5.1
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizedClientRepository the authorized client repository
     * @param filterProcessesUrl the {@code URI} where this {@code Filter} will process the authentication requests
     */
    public OAuth2ClientAuthorizedAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                      OAuth2AuthorizedClientRepository authorizedClientRepository,
                                                      OAuth2UserService<OAuth2UserRequest, OAuth2User> userService,
                                                      String filterProcessesUrl) {
        super(filterProcessesUrl);
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        Assert.notNull(userService, "userService cannot be null");

        String resolverProcessesUri = DEFAULT_RESOLVER_PROCESSES_URI;
        if(DEFAULT_FILTER_PROCESSES_URI.equals(filterProcessesUrl)){
            resolverProcessesUri = DEFAULT_RESOLVER_PROCESSES_URI;
        }else{
            resolverProcessesUri = filterProcessesUrl.replace("/*","");
        }
        this.userService = userService;
        this.oAuth2ClientAuthorizedResolver = new OAuth2ClientAuthorizedResolver(
                clientRegistrationRepository,authorizedClientRepository,
                resolverProcessesUri);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        if(oAuth2ErrorRefererRequestMatcher.matches(request)){
            OAuth2Error oauth2Error = oAuth2ErrorResolver.resolve(request);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        OAuth2AuthorizedClient client = this.oAuth2ClientAuthorizedResolver.resolve(request);
        if (client == null) {
            String registrationId = this.oAuth2ClientAuthorizedResolver.resolveRegistrationId(request);
            OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
                    "Authorized client not found with Id: " + registrationId, null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        ClientRegistration clientRegistration = client.getClientRegistration();
        OAuth2AccessToken accessToken = client.getAccessToken();

        OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(
                clientRegistration, accessToken, Collections.emptyMap()));

        Collection<? extends GrantedAuthority> mappedAuthorities =
                this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

        Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);

        OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
                oauth2User,
                mappedAuthorities,
                clientRegistration.getRegistrationId());
        oauth2Authentication.setDetails(authenticationDetails);

        return oauth2Authentication;
    }

    /**
     * Sets the {@link GrantedAuthoritiesMapper} used for mapping {@link OAuth2User#getAuthorities()}
     * to a new set of authorities which will be associated to the {@link OAuth2LoginAuthenticationToken}.
     *
     * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
     */
    public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
        this.authoritiesMapper = authoritiesMapper;
    }

}
