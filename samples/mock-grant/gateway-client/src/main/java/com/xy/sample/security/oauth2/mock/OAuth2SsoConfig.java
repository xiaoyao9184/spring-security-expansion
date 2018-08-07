package com.xy.sample.security.oauth2.mock;

import com.xy.spring.security.oauth2.mock.client.MockAccessTokenProvider;
import com.xy.spring.security.oauth2.mock.client.MockResourceDetails;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.DefaultUserInfoRestTemplateFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
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

import java.util.Arrays;
import java.util.List;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@Configuration
@EnableOAuth2Sso
public class OAuth2SsoConfig extends WebSecurityConfigurerAdapter {


//    @Bean
//    public OAuth2ClientAuthenticationProcessingFilter mockOAuth2ClientAuthenticationProcessingFilter(
//            @Autowired @Lazy AuthenticationManager authenticationManager,
//            @Autowired @Lazy ResourceServerTokenServices tokenServices,
//            @Autowired @Lazy OAuth2ProtectedResourceDetails resourceDetails,
//            @Autowired @Lazy OAuth2ClientContext context
//    ){
//        MockResourceDetails details = new MockResourceDetails();
//        details.setAccessTokenUri(resourceDetails.getAccessTokenUri());
//        details.setClientId(resourceDetails.getClientId());
//        details.setClientSecret(resourceDetails.getClientSecret());
//
//        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
//                Arrays.<AccessTokenProvider> asList(
//                        new AuthorizationCodeAccessTokenProvider(),
//                        new ImplicitAccessTokenProvider(),
//                        new ResourceOwnerPasswordAccessTokenProvider(),
//                        new ClientCredentialsAccessTokenProvider(),
//                        new MockAccessTokenProvider()
//                ));
//
//        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details, context);
//        oAuth2RestTemplate.setAccessTokenProvider(accessTokenProvider);
//
//        OAuth2ClientAuthenticationProcessingFilter filter =
//                new OAuth2ClientAuthenticationProcessingFilter("login");
//        filter.setAuthenticationManager(authenticationManager);
//        filter.setTokenServices(tokenServices);
//        filter.setRestTemplate(oAuth2RestTemplate);
//        return filter;
//    }


//    @Bean
//    public MockResourceDetails mockResourceDetails(
//            ObjectProvider<OAuth2ProtectedResourceDetails> details) {
//        MockResourceDetails details2 = new MockResourceDetails();
//        details2.setAccessTokenUri(details.getIfAvailable().getAccessTokenUri());
//        details2.setClientId(details.getIfAvailable().getClientId());
//        details2.setClientSecret(details.getIfAvailable().getClientSecret());
//        return details2;
//    }
//
//    @Bean
//    public UserInfoRestTemplateCustomizer userInfoRestTemplateCustomizer(){
//        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
//                Arrays.<AccessTokenProvider> asList(
//                        new AuthorizationCodeAccessTokenProvider(),
//                        new ImplicitAccessTokenProvider(),
//                        new ResourceOwnerPasswordAccessTokenProvider(),
//                        new ClientCredentialsAccessTokenProvider(),
//                        new MockAccessTokenProvider()
//                ));
//
//        return new UserInfoRestTemplateCustomizer() {
//            @Override
//            public void customize(OAuth2RestTemplate template) {
//                template.setAccessTokenProvider(accessTokenProvider);
//            }
//        };
//    }

    @Bean
    public OAuth2RestTemplate oAuth2RestTemplate(
            @Autowired OAuth2ProtectedResourceDetails resourceDetails,
            @Autowired OAuth2ClientContext context
    ){
        MockResourceDetails details = new MockResourceDetails();
        details.setAccessTokenUri(resourceDetails.getAccessTokenUri());
        details.setClientId(resourceDetails.getClientId());
        details.setClientSecret(resourceDetails.getClientSecret());

        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
                Arrays.<AccessTokenProvider> asList(
                        new AuthorizationCodeAccessTokenProvider(),
                        new ImplicitAccessTokenProvider(),
                        new ResourceOwnerPasswordAccessTokenProvider(),
                        new ClientCredentialsAccessTokenProvider(),
                        new MockAccessTokenProvider()
                ));

        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details, context);
        oAuth2RestTemplate.setAccessTokenProvider(accessTokenProvider);

        return oAuth2RestTemplate;
    }

    @Bean
    public UserInfoRestTemplateFactory userInfoRestTemplateFactory(
            @Autowired OAuth2ProtectedResourceDetails resourceDetails,
            @Autowired OAuth2ClientContext context){
        return new UserInfoRestTemplateFactory(){

            @Override
            public OAuth2RestTemplate getUserInfoRestTemplate() {
                MockResourceDetails details = new MockResourceDetails();
                details.setAccessTokenUri(resourceDetails.getAccessTokenUri());
                details.setClientId(resourceDetails.getClientId());
                details.setClientSecret(resourceDetails.getClientSecret());

                AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(
                        Arrays.<AccessTokenProvider> asList(
                                new AuthorizationCodeAccessTokenProvider(),
                                new ImplicitAccessTokenProvider(),
                                new ResourceOwnerPasswordAccessTokenProvider(),
                                new ClientCredentialsAccessTokenProvider(),
                                new MockAccessTokenProvider()
                        ));

                OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details, context);
                oAuth2RestTemplate.setAccessTokenProvider(accessTokenProvider);

                return oAuth2RestTemplate;
            }
        };
    }


//    @Autowired
//    private OAuth2ClientAuthenticationProcessingFilter mockOAuth2ClientAuthenticationProcessingFilter;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterAfter(mockOAuth2ClientAuthenticationProcessingFilter,
//                OAuth2ClientAuthenticationProcessingFilter.class);
//    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .requestMatchers()
                    .anyRequest()
                    .and()
                .authorizeRequests()
                    .anyRequest().fullyAuthenticated()
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    .and()
                .csrf().disable();
    }
}
