package com.xy.spring.security.oauth2.client;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
public class OAuth2ImplicitGrantFilter extends OncePerRequestFilter {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final AuthenticationManager authenticationManager;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Constructs an {@code OAuth2ImplicitGrantFilter} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizedClientRepository the authorized client repository
     * @param authenticationManager the authentication manager
     * @param authorizationRequestBaseUri authorization request base URI
     */
    public OAuth2ImplicitGrantFilter(ClientRegistrationRepository clientRegistrationRepository,
                                     OAuth2AuthorizedClientRepository authorizedClientRepository,
                                     AuthenticationManager authenticationManager,
                                     String authorizationRequestBaseUri) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be null");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (matchesTokenRequest(request)) {
            processAuthorizationResponse(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean matchesTokenRequest(HttpServletRequest request) {
        return Optional.of(request)
                .map(this::resolveRegistrationId)
                .map(this.clientRegistrationRepository::findByRegistrationId)
                .filter(cr -> AuthorizationGrantType.IMPLICIT.equals(cr.getAuthorizationGrantType()))
                .filter(cr -> {
                    MultiValueMap<String, String> params = OAuth2AuthorizationRequestUtils.toMultiMap(request.getParameterMap());
                    return OAuth2AuthorizationRequestUtils.isTokenRequest(params);
                })
                .isPresent();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        MultiValueMap<String, String> params = OAuth2AuthorizationRequestUtils.toMultiMap(request.getParameterMap());
        return params.getFirst(OAuth2ParameterNames.REGISTRATION_ID);
    }

    private void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String redirectUri = UrlUtils.buildFullRequestUrl(request);
        String registrationId = resolveRegistrationId(request);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

        MultiValueMap<String, String> params = OAuth2AuthorizationRequestUtils.toMultiMap(request.getParameterMap());
        String access_token = OAuth2AuthorizationRequestUtils.removeAccessToken(params);
        String expires_in = OAuth2AuthorizationRequestUtils.removeExpiresIn(params);
        String token_type = OAuth2AuthorizationRequestUtils.removeTokenType(params);
        String scope = OAuth2AuthorizationRequestUtils.removeScope(params);

        OAuth2ImplicitAuthenticationToken authenticationRequest = new OAuth2ImplicitAuthenticationToken(
                clientRegistration, access_token, expires_in, token_type, scope, params);
        authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

        OAuth2ImplicitAuthenticationToken authenticationResult;

        try {
            authenticationResult = (OAuth2ImplicitAuthenticationToken)
                    this.authenticationManager.authenticate(authenticationRequest);
        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error error = ex.getError();
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                    .fromUriString(redirectUri)
                    .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
            if (!StringUtils.isEmpty(error.getDescription())) {
                uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
            }
            if (!StringUtils.isEmpty(error.getUri())) {
                uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
            }
            this.redirectStrategy.sendRedirect(request, response, uriBuilder.build().encode().toString());
            return;
        }

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        String principalName = currentAuthentication != null ? currentAuthentication.getName() : "anonymousUser";

        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(),
                principalName,
                authenticationResult.getAccessToken(),
                authenticationResult.getRefreshToken());
        //TODO fix lost additional parameters of OAuth2ImplicitAuthenticationToken
//        authenticationResult.getAdditionalParameters();

        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, currentAuthentication, request, response);

        this.redirectStrategy.sendRedirect(request, response, redirectUri);
    }

}
