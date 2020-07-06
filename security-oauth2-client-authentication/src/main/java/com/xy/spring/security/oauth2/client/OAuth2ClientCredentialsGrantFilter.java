package com.xy.spring.security.oauth2.client;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
public class OAuth2ClientCredentialsGrantFilter extends OncePerRequestFilter {
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private static final char PATH_DELIMITER = '/';
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final AuthenticationManager authenticationManager;
    private final AntPathRequestMatcher authorizationRequestMatcher;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Constructs an {@code OAuth2ClientCredentialsGrantFilter} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizedClientRepository the authorized client repository
     * @param authenticationManager the authentication manager
     * @param authorizationRequestBaseUri authorization request base URI
     */
    public OAuth2ClientCredentialsGrantFilter(
            ClientRegistrationRepository clientRegistrationRepository,
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
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (matchesAuthorizationResponse(request)) {
            processAuthorizationResponse(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean matchesAuthorizationResponse(HttpServletRequest request) {
        return Optional.of(request)
                .map(this::resolveRegistrationId)
                .map(this.clientRegistrationRepository::findByRegistrationId)
                .filter(cr -> AuthorizationGrantType.CLIENT_CREDENTIALS.equals(cr.getAuthorizationGrantType()))
                .isPresent();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher
                    .matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }

    private void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String registrationId = resolveRegistrationId(request);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

        String redirectUriStr = expandRedirectUri(request, clientRegistration, "login");

        OAuth2ClientCredentialsAuthenticationToken authenticationRequest =
                new OAuth2ClientCredentialsAuthenticationToken(clientRegistration);
        authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

        OAuth2ClientCredentialsAuthenticationToken authenticationResult;

        try {
            authenticationResult = (OAuth2ClientCredentialsAuthenticationToken)
                    this.authenticationManager.authenticate(authenticationRequest);
        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error error = ex.getError();
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                    .fromUriString(redirectUriStr)
                    .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
            if (!StringUtils.isEmpty(error.getDescription())) {
                uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
            }
            if (!StringUtils.isEmpty(error.getUri())) {
                uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
            }

            //remove authorized client when error
            Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
            this.authorizedClientRepository.removeAuthorizedClient(registrationId,currentAuthentication,request,response);

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

        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, currentAuthentication, request, response);

        this.redirectStrategy.sendRedirect(request, response, redirectUriStr);
    }


    /**
     * Expands the {@link ClientRegistration#getRedirectUriTemplate()} with following provided variables:<br/>
     * - baseUrl (e.g. https://localhost/app) <br/>
     * - baseScheme (e.g. https) <br/>
     * - baseHost (e.g. localhost) <br/>
     * - basePort (e.g. :8080) <br/>
     * - basePath (e.g. /app) <br/>
     * - registrationId (e.g. google) <br/>
     * - action (e.g. login) <br/>
     * <p/>
     * Null variables are provided as empty strings.
     * <p/>
     * Default redirectUriTemplate is: {@link org.springframework.security.config.oauth2.client}.CommonOAuth2Provider#DEFAULT_REDIRECT_URL
     *
     * @return expanded URI
     */
    private static String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration, String action) {
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("registrationId", clientRegistration.getRegistrationId());

        UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();
        String scheme = uriComponents.getScheme();
        uriVariables.put("baseScheme", scheme == null ? "" : scheme);
        String host = uriComponents.getHost();
        uriVariables.put("baseHost", host == null ? "" : host);
        // following logic is based on HierarchicalUriComponents#toUriString()
        int port = uriComponents.getPort();
        uriVariables.put("basePort", port == -1 ? "" : ":" + port);
        String path = uriComponents.getPath();
        if (StringUtils.hasLength(path)) {
            if (path.charAt(0) != PATH_DELIMITER) {
                path = PATH_DELIMITER + path;
            }
        }
        uriVariables.put("basePath", path == null ? "" : path);
        uriVariables.put("baseUrl", uriComponents.toUriString());

        uriVariables.put("action", action == null ? "" : action);

        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
                .buildAndExpand(uriVariables)
                .toUriString();
    }
}
