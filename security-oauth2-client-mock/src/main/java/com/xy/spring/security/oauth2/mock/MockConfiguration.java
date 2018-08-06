package com.xy.spring.security.oauth2.mock;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
@Configuration
@EnableConfigurationProperties(MockTokenEndpointProperties.class)
@Import({ MockTokenGranterAuthorizationServerConfigurer.class, })
public class MockConfiguration {

    @Bean
    public MockUsernameDaoAuthenticationProvider mockDaoAuthenticationProvider(
            @Autowired UserDetailsService userDetailsService){
        MockUsernameDaoAuthenticationProvider mockUsernameDaoAuthenticationProvider = new MockUsernameDaoAuthenticationProvider();
        mockUsernameDaoAuthenticationProvider.setUserDetailsService(userDetailsService);
        mockUsernameDaoAuthenticationProvider.setPasswordEncoder(new AlwaysMatchePasswordEncoder());
        return mockUsernameDaoAuthenticationProvider;
    }

    @Autowired
    private MockUsernameDaoAuthenticationProvider mockUsernameDaoAuthenticationProvider;

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(mockUsernameDaoAuthenticationProvider);
    }

    /*
    MockTokenAuthorizationServerSecurityConfiguration
    MockTokenAuthorizationServerEndpointsConfiguration
     */

//    @Configuration
//    @AutoConfigureAfter(ResourceServerConfiguration.class)
////    @Conditional(OAuth2ResourceServerConfiguration.ResourceServerCondition.class)
//    @ConditionalOnClass({ EnableResourceServer.class, SecurityProperties.class })
//    @ConditionalOnWebApplication
//
//    @ConditionalOnBean(OAuth2ResourceServerConfiguration.class)
////    @ConditionalOnBean(ResourceServerConfiguration.class)
//    @ConditionalOnProperty(name = MockTokenEndpointProperties.PROPERTIE_ENABLE, havingValue = "true", matchIfMissing = true)
//    public static class MockTokenEndpointConfiguration{
//
//        private final ResourceServerProperties resource;
//
//        public MockTokenEndpointConfiguration(ResourceServerProperties resource) {
//            this.resource = resource;
//        }
////        @Bean
////        @ConditionalOnMissingBean(ResourceServerConfigurer.class)
////        public ResourceServerConfigurer resourceServer() {
////            return new OAuth2ResourceServerConfiguration.ResourceSecurityConfigurer(this.resource);
////        }
////
//        @Bean
//        public MockTokenEndpointResourceServerConfigurer mockTokenGranterResourceServerConfigurer(
//                @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
//                @Autowired AuthorizationServerEndpointsConfiguration endpoints
//        ) throws Exception {
//            MockTokenEndpointResourceServerConfigurer resourceServerConfigurer = new MockTokenEndpointResourceServerConfigurer();
//            resourceServerConfigurer.setOrder(mockTokenEndpointProperties.getOrder());
//            resourceServerConfigurer.setAccess(mockTokenEndpointProperties.getAccess());
//            resourceServerConfigurer.setHandlerMapping(endpoints.oauth2EndpointHandlerMapping());
//            resourceServerConfigurer.setResourceId(resource.getId());
//            return resourceServerConfigurer;
//        }
//
//        @Bean
//        public MockTokenEndpoint mockTokenEndpoint(
//                @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
//                @Autowired TokenEndpoint tokenEndpoint
//        ){
//            MockTokenEndpoint endpoint = new MockTokenEndpoint();
//            endpoint.setClientId(mockTokenEndpointProperties.getClientId());
//            endpoint.setClientSecret(mockTokenEndpointProperties.getClientSecret());
//            endpoint.setTokenEndpoint(tokenEndpoint);
//            return endpoint;
//        }
//    }


//    @ConditionalOnBean(ResourceServerConfiguration.class)
//    @ConditionalOnBean(ResourceServerConfigurer.class)
//    @ConditionalOnMissingBean(ResourceServerConfigurer.class)
//    @ConditionalOnProperty(name = MockTokenEndpointProperties.PROPERTIE_ENABLE, havingValue = "true", matchIfMissing = true)
//    @Bean
//    public MockTokenEndpointResourceServerConfigurer mockTokenGranterResourceServerConfigurer(
//            @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
//            @Autowired AuthorizationServerEndpointsConfiguration endpoints
//    ) throws Exception {
//        MockTokenEndpointResourceServerConfigurer resourceServerConfigurer = new MockTokenEndpointResourceServerConfigurer();
//        resourceServerConfigurer.setOrder(mockTokenEndpointProperties.getOrder());
//        resourceServerConfigurer.setAccess(mockTokenEndpointProperties.getAccess());
//        resourceServerConfigurer.setHandlerMapping(endpoints.oauth2EndpointHandlerMapping());
//        return resourceServerConfigurer;
//    }
//
////    @ConditionalOnBean(ResourceServerConfiguration.class)
//    @ConditionalOnProperty(name = MockTokenEndpointProperties.PROPERTIE_ENABLE, havingValue = "true", matchIfMissing = true)
//    @Bean
//    public MockTokenEndpoint mockTokenEndpoint(
//            @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
//            @Autowired TokenEndpoint tokenEndpoint
//    ){
//        MockTokenEndpoint endpoint = new MockTokenEndpoint();
//        endpoint.setClientId(mockTokenEndpointProperties.getClientId());
//        endpoint.setClientSecret(mockTokenEndpointProperties.getClientSecret());
//        endpoint.setTokenEndpoint(tokenEndpoint);
//        return endpoint;
//    }

}
