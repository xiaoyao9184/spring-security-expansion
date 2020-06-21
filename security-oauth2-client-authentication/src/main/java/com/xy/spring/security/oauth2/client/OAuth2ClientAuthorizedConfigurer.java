package com.xy.spring.security.oauth2.client;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 * @param <B>
 */
public class OAuth2ClientAuthorizedConfigurer<B extends HttpSecurityBuilder<B>> extends
        AbstractAuthenticationFilterConfigurer<B, OAuth2ClientAuthorizedConfigurer<B>, OAuth2ClientAuthorizedAuthenticationFilter> {
    
    private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();
    private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();
    private final RedirectionEndpointConfig redirectionEndpointConfig = new RedirectionEndpointConfig();
    private final UserInfoEndpointConfig userInfoEndpointConfig = new UserInfoEndpointConfig();

    private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient;
    private String loginPage;
    private String loginProcessingUrl = OAuth2ClientAuthorizedAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;


    /**
     * Sets the repository of client registrations.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further configuration
     */
    public OAuth2ClientAuthorizedConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
        return this;
    }

    /**
     * Sets the repository for authorized client(s).
     *
     * @since 5.1
     * @param authorizedClientRepository the authorized client repository
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further configuration
     */
    public OAuth2ClientAuthorizedConfigurer<B> authorizedClientRepository(OAuth2AuthorizedClientRepository authorizedClientRepository) {
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        this.getBuilder().setSharedObject(OAuth2AuthorizedClientRepository.class, authorizedClientRepository);
        return this;
    }

    /**
     * Sets the service for authorized client(s).
     *
     * @param authorizedClientService the authorized client service
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further configuration
     */
    public OAuth2ClientAuthorizedConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
        Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
        this.authorizedClientRepository(new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService));
        return this;
    }

    @Override
    public OAuth2ClientAuthorizedConfigurer<B> loginPage(String loginPage) {
        Assert.hasText(loginPage, "loginPage cannot be empty");
        this.loginPage = loginPage;
        return this;
    }

    @Override
    public OAuth2ClientAuthorizedConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be empty");
        this.loginProcessingUrl = loginProcessingUrl;
        return this;
    }

    /**
     * Returns the {@link OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig} for configuring the Authorization Server's Authorization Endpoint.
     *
     * @return the {@link OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig}
     */
    public OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig authorizationEndpoint() {
        return this.authorizationEndpointConfig;
    }

    /**
     * Configures the Authorization Server's Authorization Endpoint.
     *
     * @param authorizationEndpointCustomizer the {@link Customizer} to provide more options for
     * the {@link OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig}
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further customizations
     */
    public OAuth2ClientAuthorizedConfigurer<B> authorizationEndpoint(Customizer<OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig> authorizationEndpointCustomizer) {
        authorizationEndpointCustomizer.customize(this.authorizationEndpointConfig);
        return this;
    }

    /**
     * Configuration options for the Authorization Server's Authorization Endpoint.
     */
    public class AuthorizationEndpointConfig {
        private String authorizationRequestBaseUri;
        @Deprecated
        private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
        @Deprecated
        private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

        private AuthorizationEndpointConfig() {
        }

        /**
         * Sets the base {@code URI} used for authorization requests.
         *
         * @param authorizationRequestBaseUri the base {@code URI} used for authorization requests
         * @return the {@link OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
            Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
            this.authorizationRequestBaseUri = authorizationRequestBaseUri;
            return this;
        }

        /**
         * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
         *
         * @since 5.1
         * @param authorizationRequestResolver the resolver used for resolving {@link OAuth2AuthorizationRequest}'s
         * @return the {@link OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig authorizationRequestResolver(OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
            Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
            this.authorizationRequestResolver = authorizationRequestResolver;
            return this;
        }

        /**
         * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
         *
         * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
         * @return the {@link OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.AuthorizationEndpointConfig authorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
            Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
            this.authorizationRequestRepository = authorizationRequestRepository;
            return this;
        }

        /**
         * Returns the {@link OAuth2ClientAuthorizedConfigurer} for further configuration.
         *
         * @return the {@link OAuth2ClientAuthorizedConfigurer}
         */
        public OAuth2ClientAuthorizedConfigurer<B> and() {
            return OAuth2ClientAuthorizedConfigurer.this;
        }
    }

    /**
     * Returns the {@link OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig} for configuring the Authorization Server's Token Endpoint.
     *
     * @return the {@link OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig}
     */
    public OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig tokenEndpoint() {
        return this.tokenEndpointConfig;
    }

    /**
     * Configures the Authorization Server's Token Endpoint.
     *
     * @param tokenEndpointCustomizer the {@link Customizer} to provide more options for
     * the {@link OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig}
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further customizations
     * @throws Exception
     */
    public OAuth2ClientAuthorizedConfigurer<B> tokenEndpoint(Customizer<OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig> tokenEndpointCustomizer) {
        tokenEndpointCustomizer.customize(this.tokenEndpointConfig);
        return this;
    }

    /**
     * Configuration options for the Authorization Server's Token Endpoint.
     */
    public class TokenEndpointConfig {
        //TODO support OAuth2ClientCredentialsGrantRequest
        private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient;

        private TokenEndpointConfig() {
        }

        /**
         * Sets the client used for requesting the access token credential from the Token Endpoint.
         *
         * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
         * @return the {@link OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig accessTokenResponseClient(
                OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient) {

            Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
            this.accessTokenResponseClient = accessTokenResponseClient;
            return this;
        }

        /**
         * Returns the {@link OAuth2ClientAuthorizedConfigurer} for further configuration.
         *
         * @return the {@link OAuth2ClientAuthorizedConfigurer}
         */
        public OAuth2ClientAuthorizedConfigurer<B> and() {
            return OAuth2ClientAuthorizedConfigurer.this;
        }
    }

    /**
     * Returns the {@link OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig} for configuring the Client's Redirection Endpoint.
     *
     * @return the {@link OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig}
     */
    public OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig redirectionEndpoint() {
        return this.redirectionEndpointConfig;
    }

    /**
     * Configures the Client's Redirection Endpoint.
     *
     * @param redirectionEndpointCustomizer the {@link Customizer} to provide more options for
     * the {@link OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig}
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further customizations
     */
    public OAuth2ClientAuthorizedConfigurer<B> redirectionEndpoint(Customizer<OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig> redirectionEndpointCustomizer) {
        redirectionEndpointCustomizer.customize(this.redirectionEndpointConfig);
        return this;
    }

    /**
     * Configuration options for the Client's Redirection Endpoint.
     */
    public class RedirectionEndpointConfig {
        private String authorizationResponseBaseUri;

        private RedirectionEndpointConfig() {
        }

        /**
         * Sets the {@code URI} where the authorization response will be processed.
         *
         * @param authorizationResponseBaseUri the {@code URI} where the authorization response will be processed
         * @return the {@link OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.RedirectionEndpointConfig baseUri(String authorizationResponseBaseUri) {
            Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
            this.authorizationResponseBaseUri = authorizationResponseBaseUri;
            return this;
        }

        /**
         * Returns the {@link OAuth2ClientAuthorizedConfigurer} for further configuration.
         *
         * @return the {@link OAuth2ClientAuthorizedConfigurer}
         */
        public OAuth2ClientAuthorizedConfigurer<B> and() {
            return OAuth2ClientAuthorizedConfigurer.this;
        }
    }

    /**
     * Returns the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig} for configuring the Authorization Server's UserInfo Endpoint.
     *
     * @return the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig}
     */
    public OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig userInfoEndpoint() {
        return this.userInfoEndpointConfig;
    }

    /**
     * Configures the Authorization Server's UserInfo Endpoint.
     *
     * @param userInfoEndpointCustomizer the {@link Customizer} to provide more options for
     * the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig}
     * @return the {@link OAuth2ClientAuthorizedConfigurer} for further customizations
     */
    public OAuth2ClientAuthorizedConfigurer<B> userInfoEndpoint(Customizer<OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig> userInfoEndpointCustomizer) {
        userInfoEndpointCustomizer.customize(this.userInfoEndpointConfig);
        return this;
    }

    /**
     * Configuration options for the Authorization Server's UserInfo Endpoint.
     */
    public class UserInfoEndpointConfig {
        private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
        private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;
        private Map<String, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();

        private UserInfoEndpointConfig() {
        }

        /**
         * Sets the OAuth 2.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint.
         *
         * @param userService the OAuth 2.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint
         * @return the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig userService(OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
            Assert.notNull(userService, "userService cannot be null");
            this.userService = userService;
            return this;
        }

        /**
         * Sets the OpenID Connect 1.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint.
         *
         * @param oidcUserService the OpenID Connect 1.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint
         * @return the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig oidcUserService(OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) {
            Assert.notNull(oidcUserService, "oidcUserService cannot be null");
            this.oidcUserService = oidcUserService;
            return this;
        }

        /**
         * Sets a custom {@link OAuth2User} type and associates it to the provided
         * client {@link ClientRegistration#getRegistrationId() registration identifier}.
         *
         * @param customUserType a custom {@link OAuth2User} type
         * @param clientRegistrationId the client registration identifier
         * @return the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig customUserType(Class<? extends OAuth2User> customUserType, String clientRegistrationId) {
            Assert.notNull(customUserType, "customUserType cannot be null");
            Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
            this.customUserTypes.put(clientRegistrationId, customUserType);
            return this;
        }

        /**
         * Sets the {@link GrantedAuthoritiesMapper} used for mapping {@link OAuth2User#getAuthorities()}.
         *
         * @param userAuthoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
         * @return the {@link OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.UserInfoEndpointConfig userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
            Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
            OAuth2ClientAuthorizedConfigurer.this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class, userAuthoritiesMapper);
            return this;
        }

        /**
         * Returns the {@link OAuth2ClientAuthorizedConfigurer} for further configuration.
         *
         * @return the {@link OAuth2ClientAuthorizedConfigurer}
         */
        public OAuth2ClientAuthorizedConfigurer<B> and() {
            return OAuth2ClientAuthorizedConfigurer.this;
        }
    }
    
    
    
    

    @Override
    public void init(B http) throws Exception {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = this.getOAuth2UserService();
        OAuth2ClientAuthorizedAuthenticationFilter authenticationFilter =
                new OAuth2ClientAuthorizedAuthenticationFilter(
                        OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(this.getBuilder()),
                        OAuth2ClientAuthorizedConfigurerUtils.getAuthorizedClientRepository(this.getBuilder()),
                        oauth2UserService,
                        this.loginProcessingUrl);
        GrantedAuthoritiesMapper userAuthoritiesMapper = this.getGrantedAuthoritiesMapper();
        if (userAuthoritiesMapper != null) {
            authenticationFilter.setAuthoritiesMapper(userAuthoritiesMapper);
        }

        this.registerFilterOrder(http);
        this.setAuthenticationFilter(authenticationFilter);
        super.loginProcessingUrl(this.loginProcessingUrl);

        if (this.loginPage != null) {
            // Set custom login page
            super.loginPage(this.loginPage);
            super.init(http);
        } else {
            Map<String, String> loginUrlToClientName = this.getLoginLinks();
            if (loginUrlToClientName.size() == 1) {
                // Setup auto-redirect to provider login page
                // when only 1 client is configured
                this.updateAuthenticationDefaults();
                this.updateAccessDefaults(http);
                String providerLoginPage = loginUrlToClientName.keySet().iterator().next();
                this.registerAuthenticationEntryPoint(http, this.getLoginEntryPoint(http, providerLoginPage));
            } else {
                super.init(http);
            }
        }

        //support Authentication by password grant
        OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient =
                this.tokenEndpointConfig.accessTokenResponseClient;
        if (accessTokenResponseClient == null) {
            accessTokenResponseClient = new DefaultPasswordTokenResponseClient();
        }
        OAuth2PasswordAuthenticationProvider authorizationCodeAuthenticationProvider =
                new OAuth2PasswordAuthenticationProvider(accessTokenResponseClient);
        http.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));

        //TODO support client-credentials grant by AuthenticationProvider

    }

    @Override
    public void configure(B http) throws Exception {
        OAuth2PasswordGrantFilter authorizationCodeGrantFilter = createPasswordGrantFilter(http);
        http.addFilterBefore(postProcess(authorizationCodeGrantFilter),OAuth2AuthorizationRequestRedirectFilter.class);

        //TODO support client-credentials grant by Filter






        OAuth2ClientAuthorizedAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
        if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
            authenticationFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
        }
//        if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
//            authenticationFilter.setAuthorizationRequestRepository(
//                    this.authorizationEndpointConfig.authorizationRequestRepository);
//        }
        super.configure(http);
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl);
    }


    @SuppressWarnings("ConstantConditions")
    private void registerFilterOrder(B http) {
        HttpSecurity hs = (HttpSecurity) http;

        Field f = ReflectionUtils.findField(HttpSecurity.class,"comparator");
        f.setAccessible(true);
        Object comparator = ReflectionUtils.getField(f,hs);

        Method m = ReflectionUtils.findMethod(comparator.getClass(),"registerAfter", Class.class, Class.class);
        m.setAccessible(true);
        ReflectionUtils.invokeMethod(m,comparator,
                OAuth2ClientAuthorizedAuthenticationFilter.class, OAuth2AuthorizationCodeGrantFilter.class);
    }


    private OAuth2PasswordGrantFilter createPasswordGrantFilter(B http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2PasswordGrantFilter authorizationCodeGrantFilter;

        //TODO support config DefaultOAuth2AuthorizationRequestResolver

        //config uri without resolver
        String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
        if (authorizationRequestBaseUri == null) {
            authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        }

        authorizationCodeGrantFilter = new OAuth2PasswordGrantFilter(
                OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(http),
                OAuth2ClientAuthorizedConfigurerUtils.getAuthorizedClientRepository(http),
                authenticationManager,
                authorizationRequestBaseUri);

        return authorizationCodeGrantFilter;
    }


    private GrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
        GrantedAuthoritiesMapper grantedAuthoritiesMapper =
                this.getBuilder().getSharedObject(GrantedAuthoritiesMapper.class);
        if (grantedAuthoritiesMapper == null) {
            grantedAuthoritiesMapper = this.getGrantedAuthoritiesMapperBean();
            if (grantedAuthoritiesMapper != null) {
                this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class, grantedAuthoritiesMapper);
            }
        }
        return grantedAuthoritiesMapper;
    }

    private GrantedAuthoritiesMapper getGrantedAuthoritiesMapperBean() {
        Map<String, GrantedAuthoritiesMapper> grantedAuthoritiesMapperMap =
                BeanFactoryUtils.beansOfTypeIncludingAncestors(
                        this.getBuilder().getSharedObject(ApplicationContext.class),
                        GrantedAuthoritiesMapper.class);
        return (!grantedAuthoritiesMapperMap.isEmpty() ? grantedAuthoritiesMapperMap.values().iterator().next() : null);
    }

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> getOAuth2UserService() {
        if (this.userInfoEndpointConfig.userService != null) {
            return this.userInfoEndpointConfig.userService;
        }
        ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2UserService.class, OAuth2UserRequest.class, OAuth2User.class);
        OAuth2UserService<OAuth2UserRequest, OAuth2User> bean = getBeanOrNull(type);
        if (bean == null) {
            if (!this.userInfoEndpointConfig.customUserTypes.isEmpty()) {
                List<OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new ArrayList<>();
                userServices.add(new CustomUserTypesOAuth2UserService(this.userInfoEndpointConfig.customUserTypes));
                userServices.add(new DefaultOAuth2UserService());
                return new DelegatingOAuth2UserService<>(userServices);
            } else {
                return new DefaultOAuth2UserService();
            }
        }

        return bean;
    }

    private <T> T getBeanOrNull(ResolvableType type) {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        if (context == null) {
            return null;
        }
        String[] names =  context.getBeanNamesForType(type);
        if (names.length == 1) {
            return (T) context.getBean(names[0]);
        }
        return null;
    }
    
    @SuppressWarnings("unchecked")
    private Map<String, String> getLoginLinks() {
        Iterable<ClientRegistration> clientRegistrations = null;
        ClientRegistrationRepository clientRegistrationRepository =
                OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(this.getBuilder());
        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
        if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
        }
        if (clientRegistrations == null) {
            return Collections.emptyMap();
        }

        String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri != null ?
                this.authorizationEndpointConfig.authorizationRequestBaseUri :
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        Map<String, String> loginUrlToClientName = new HashMap<>();
        clientRegistrations.forEach(registration -> loginUrlToClientName.put(
                authorizationRequestBaseUri + "/" + registration.getRegistrationId(),
                registration.getClientName()));

        return loginUrlToClientName;
    }

    private AuthenticationEntryPoint getLoginEntryPoint(B http, String providerLoginPage) {
        RequestMatcher loginPageMatcher = new AntPathRequestMatcher(this.getLoginPage());
        RequestMatcher faviconMatcher = new AntPathRequestMatcher("/favicon.ico");
        RequestMatcher defaultEntryPointMatcher = this.getAuthenticationEntryPointMatcher(http);
        RequestMatcher defaultLoginPageMatcher = new AndRequestMatcher(
                new OrRequestMatcher(loginPageMatcher, faviconMatcher), defaultEntryPointMatcher);

        RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
                new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));

        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(new AndRequestMatcher(notXRequestedWith, new NegatedRequestMatcher(defaultLoginPageMatcher)),
                new LoginUrlAuthenticationEntryPoint(providerLoginPage));

        DelegatingAuthenticationEntryPoint loginEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
        loginEntryPoint.setDefaultEntryPoint(this.getAuthenticationEntryPoint());

        return loginEntryPoint;
    }


}