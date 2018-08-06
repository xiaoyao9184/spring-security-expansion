package com.xy.spring.security.oauth2.mock;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
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

    @ConditionalOnProperty(name = MockTokenEndpointProperties.PROPERTIE_ENABLE, havingValue = "true", matchIfMissing = true)
    @Bean
    public MockTokenEndpointResourceServerConfigurer mockTokenGranterResourceServerConfigurer(
            @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
            @Autowired AuthorizationServerEndpointsConfiguration endpoints
    ) throws Exception {
        MockTokenEndpointResourceServerConfigurer resourceServerConfigurer = new MockTokenEndpointResourceServerConfigurer();
        resourceServerConfigurer.setOrder(mockTokenEndpointProperties.getOrder());
        resourceServerConfigurer.setAccess(mockTokenEndpointProperties.getAccess());
        resourceServerConfigurer.setHandlerMapping(endpoints.oauth2EndpointHandlerMapping());
        return resourceServerConfigurer;
    }

    @ConditionalOnProperty(name = MockTokenEndpointProperties.PROPERTIE_ENABLE, havingValue = "true", matchIfMissing = true)
    @Bean
    public MockTokenEndpoint mockTokenEndpoint(
            @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
            @Autowired TokenEndpoint tokenEndpoint
    ){
        MockTokenEndpoint endpoint = new MockTokenEndpoint();
        endpoint.setClientId(mockTokenEndpointProperties.getClientId());
        endpoint.setClientSecret(mockTokenEndpointProperties.getClientSecret());
        endpoint.setTokenEndpoint(tokenEndpoint);
        return endpoint;
    }

}
