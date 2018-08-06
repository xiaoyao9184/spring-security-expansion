package com.xy.spring.security.oauth2.password;

import com.xy.spring.security.oauth2.password.client.*;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2SsoProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.util.Arrays;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
public class OAuth2PasswordSecurityConfigurer
        extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>{

    private ApplicationContext applicationContext;

    OAuth2PasswordSecurityConfigurer(
            ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        OAuth2SsoProperties sso = this.applicationContext
                .getBean(OAuth2SsoProperties.class);
        Oauth2PasswordEndpointProperties password = this.applicationContext
                .getBean(Oauth2PasswordEndpointProperties.class);
        ResourceServerTokenServices tokenServices = this.applicationContext
                .getBean(ResourceServerTokenServices.class);
        OAuth2ProtectedResourceDetails resource = applicationContext
                .getBean(OAuth2ProtectedResourceDetails.class);
        OAuth2ClientContext context = applicationContext
                .getBean(OAuth2ClientContext.class);

        builder.addFilterAfter(
                oAuth2ClientPasswordAuthenticationProcessingFilter(sso,password,tokenServices,resource,context),
                AbstractPreAuthenticatedProcessingFilter.class);
    }

    public OAuth2ClientAuthenticationProcessingFilter oAuth2ClientPasswordAuthenticationProcessingFilter(
            OAuth2SsoProperties ssoProperties,
            Oauth2PasswordEndpointProperties endpointProperties,
            ResourceServerTokenServices tokenServices,
            OAuth2ProtectedResourceDetails resourceDetails,
            OAuth2ClientContext context
    ) {
        String endpointPath = endpointProperties.getPasswordLoginPath();
        if(endpointProperties.isUseSsoLoginPathPrefix()){
            endpointPath = ssoProperties.getLoginPath() + endpointProperties.getPasswordLoginPath();
        }

        ProxyResourceOwnerPasswordResourceDetails details = new ProxyResourceOwnerPasswordResourceDetails();
        details.setAccessTokenUri(resourceDetails.getAccessTokenUri());
        details.setClientId(resourceDetails.getClientId());
        details.setClientSecret(resourceDetails.getClientSecret());

        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
                Arrays.<AccessTokenProvider> asList(
                        new AuthorizationCodeAccessTokenProvider(),
                        new ImplicitAccessTokenProvider(),
                        new ResourceOwnerPasswordAccessTokenProvider(),
                        new ClientCredentialsAccessTokenProvider(),
                        new ProxyResourceOwnerPasswordAccessTokenProvider()
                ));

        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details, context);
        oAuth2RestTemplate.setAccessTokenProvider(accessTokenProvider);

        OAuth2ClientAuthenticationProcessingFilter filter =
                new OAuth2ClientAuthenticationProcessingFilter(endpointPath);
        filter.setTokenServices(tokenServices);
        filter.setRestTemplate(oAuth2RestTemplate);
        filter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> httpServletResponse.setStatus(200));
        return filter;
    }
}
