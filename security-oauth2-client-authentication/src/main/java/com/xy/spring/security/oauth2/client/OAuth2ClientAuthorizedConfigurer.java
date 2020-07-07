package com.xy.spring.security.oauth2.client;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

import static com.xy.spring.security.oauth2.client.OAuth2ClientAuthorizedAuthenticationFilter.REGISTRATION_ID_URI_VARIABLE_NAME;

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

    private static final RequestHeaderRequestMatcher X_REQUESTED_WITH = new RequestHeaderRequestMatcher("X-Requested-With",
            "XMLHttpRequest");
    private static final OAuth2ErrorRefererRequestMatcher REFERER_ERROR = new OAuth2ErrorRefererRequestMatcher(
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                    + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
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
        private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordAccessTokenResponseClient;
        private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsGrantAccessTokenResponseClient;

        private TokenEndpointConfig() {
        }

        /**
         * Sets the client used for requesting the access token credential from the Token Endpoint.
         *
         * @param passwordGrantAccessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
         * @return the {@link OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig passwordGrantAccessTokenResponseClient(
                OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordGrantAccessTokenResponseClient) {

            Assert.notNull(accessTokenResponseClient, "passwordAccessTokenResponseClient cannot be null");
            this.passwordAccessTokenResponseClient = passwordGrantAccessTokenResponseClient;
            return this;
        }

        /**
         * Sets the client used for requesting the access token credential from the Token Endpoint.
         *
         * @param clientCredentialsGrantAccessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
         * @return the {@link OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig} for further configuration
         */
        public OAuth2ClientAuthorizedConfigurer.TokenEndpointConfig clientCredentialsGrantAccessTokenResponseClient(
                OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsGrantAccessTokenResponseClient) {

            Assert.notNull(passwordAccessTokenResponseClient, "clientCredentialsGrantAccessTokenResponseClient cannot be null");
            this.clientCredentialsGrantAccessTokenResponseClient = clientCredentialsGrantAccessTokenResponseClient;
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


        //default login entry point
        RequestMatcher contentNegotiationRequestMatcher = this.getAuthenticationEntryPointMatcher(http);
        AuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(
                this.getLoginPage() + "?error");
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(REFERER_ERROR, new OAuth2Error401Or500EntryPoint());
        entryPoints.put(X_REQUESTED_WITH, new Http403ForbiddenEntryPoint());
        entryPoints.put(contentNegotiationRequestMatcher, authenticationEntryPoint);
        DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
        entryPoint.setDefaultEntryPoint(authenticationEntryPoint);

        //use AuthenticationEntryPointFailureHandler
        AuthenticationEntryPointFailureHandler authenticationEntryPointFailureHandler =
                new AuthenticationEntryPointFailureHandler(entryPoint);
        this.failureHandler(authenticationEntryPointFailureHandler);

//        this.failureHandler(new SimpleUrlAuthenticationFailureHandler());


        //support implicit grant authentication by AuthenticationProvider
        OAuth2ImplicitAuthenticationProvider implicitAuthenticationProvider =
                new OAuth2ImplicitAuthenticationProvider();
        http.authenticationProvider(postProcess(implicitAuthenticationProvider));

        //support password grant authentication by AuthenticationProvider
        OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordAccessTokenResponseClient =
                this.tokenEndpointConfig.passwordAccessTokenResponseClient;
        if (passwordAccessTokenResponseClient == null) {
            passwordAccessTokenResponseClient = new DefaultPasswordTokenResponseClient();
        }
        OAuth2PasswordAuthenticationProvider passwordAuthenticationProvider =
                new OAuth2PasswordAuthenticationProvider(passwordAccessTokenResponseClient);
        http.authenticationProvider(postProcess(passwordAuthenticationProvider));

        //support client-credentials grant authentication by AuthenticationProvider
        OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsGrantAccessTokenResponseClient =
                this.tokenEndpointConfig.clientCredentialsGrantAccessTokenResponseClient;
        if (clientCredentialsGrantAccessTokenResponseClient == null) {
            clientCredentialsGrantAccessTokenResponseClient = new DefaultClientCredentialsTokenResponseClient();
        }
        OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
                new OAuth2ClientCredentialsAuthenticationProvider(clientCredentialsGrantAccessTokenResponseClient);
        http.authenticationProvider(postProcess(clientCredentialsAuthenticationProvider));
    }

    @Override
    public void configure(B http) throws Exception {
        //support implicit grant request
        OAuth2ImplicitGrantFilter implicitGrantFilter = createImplicitGrantFilter(http);
        http.addFilterBefore(postProcess(implicitGrantFilter),OAuth2ClientAuthorizedAuthenticationFilter.class);

        //support password grant request
        OAuth2PasswordGrantFilter passwordGrantFilter = createPasswordGrantFilter(http);
        http.addFilterBefore(postProcess(passwordGrantFilter), OAuth2AuthorizationRequestRedirectFilter.class);

        //support client-credentials grant request
        OAuth2ClientCredentialsGrantFilter clientCredentialsGrantFilter = createClientCredentialsGrantFilter(http);
        http.addFilterBefore(postProcess(clientCredentialsGrantFilter),OAuth2PasswordGrantFilter.class);

        //password grant page
        OAuth2PasswordLoginPageGeneratingFilter passwordLoginPageGeneratingFilter = createOAuth2PasswordLoginPageGeneratingFilter(http);
        http.addFilterAfter(postProcess(passwordLoginPageGeneratingFilter),OAuth2PasswordGrantFilter.class);

        OAuth2ClientAuthorizedAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
        if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
            authenticationFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
        }
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


    private OAuth2ImplicitGrantFilter createImplicitGrantFilter(B http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2ImplicitGrantFilter implicitGrantFilter;

        //TODO support config DefaultOAuth2AuthorizationRequestResolver

        //config uri without resolver
        String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
        if (authorizationRequestBaseUri == null) {
            authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        }

        implicitGrantFilter = new OAuth2ImplicitGrantFilter(
                OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(http),
                OAuth2ClientAuthorizedConfigurerUtils.getAuthorizedClientRepository(http),
                authenticationManager,
                authorizationRequestBaseUri);

        return implicitGrantFilter;
    }

    private OAuth2PasswordGrantFilter createPasswordGrantFilter(B http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2PasswordGrantFilter passwordGrantFilter;

        //TODO support config DefaultOAuth2AuthorizationRequestResolver

        //config uri without resolver
        String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
        if (authorizationRequestBaseUri == null) {
            authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        }

        passwordGrantFilter = new OAuth2PasswordGrantFilter(
                OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(http),
                OAuth2ClientAuthorizedConfigurerUtils.getAuthorizedClientRepository(http),
                authenticationManager,
                authorizationRequestBaseUri);

        return passwordGrantFilter;
    }

    private OAuth2ClientCredentialsGrantFilter createClientCredentialsGrantFilter(B http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2ClientCredentialsGrantFilter clientCredentialsGrantFilter;

        //TODO support config DefaultOAuth2AuthorizationRequestResolver

        //config uri without resolver
        String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
        if (authorizationRequestBaseUri == null) {
            authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        }

        clientCredentialsGrantFilter = new OAuth2ClientCredentialsGrantFilter(
                OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(http),
                OAuth2ClientAuthorizedConfigurerUtils.getAuthorizedClientRepository(http),
                authenticationManager,
                authorizationRequestBaseUri);

        return clientCredentialsGrantFilter;
    }

    private OAuth2PasswordLoginPageGeneratingFilter createOAuth2PasswordLoginPageGeneratingFilter(B http) {
        OAuth2PasswordLoginPageGeneratingFilter passwordLoginPageGeneratingFilter;

        //TODO support config DefaultOAuth2AuthorizationRequestResolver

        //config uri without resolver
        String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
        if (authorizationRequestBaseUri == null) {
            authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        }

        passwordLoginPageGeneratingFilter = new OAuth2PasswordLoginPageGeneratingFilter(
                OAuth2ClientAuthorizedConfigurerUtils.getClientRegistrationRepository(http),
                OAuth2ClientAuthorizedConfigurerUtils.getAuthorizedClientRepository(http),
                authorizationRequestBaseUri);

        return passwordLoginPageGeneratingFilter;
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
            List<OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new ArrayList<>();
            if (!this.userInfoEndpointConfig.customUserTypes.isEmpty()) {
                userServices.add(new CustomUserTypesOAuth2UserService(this.userInfoEndpointConfig.customUserTypes));
            }
            ResolvableType typeEnvironment = ResolvableType.forType(Environment.class);
            Environment environment = getBeanOrNull(typeEnvironment);
            UAAClientOAuth2UserService clientOAuth2UserService = new UAAClientOAuth2UserService(environment);
            userServices.add(clientOAuth2UserService);

            DefaultOAuth2UserService oauth2UserService = new DefaultOAuth2UserService();
            userServices.add(oauth2UserService);
            return new DelegatingOAuth2UserService<>(userServices);
        }

        return bean;
    }

    private <T> T getBeanOrNull(ResolvableType type) {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        if (context == null) {
            return null;
        }
        String[] names = context.getBeanNamesForType(type);
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
