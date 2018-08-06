package com.xy.spring.security.oauth2.mock;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
@Configuration
@AutoConfigureAfter(ResourceServerConfiguration.class)
@ConditionalOnClass({ EnableResourceServer.class, SecurityProperties.class, ResourceServerProperties.class })
@ConditionalOnWebApplication
@ConditionalOnBean(OAuth2ResourceServerConfiguration.class)
@EnableConfigurationProperties(MockTokenEndpointProperties.class)
@ConditionalOnProperty(name = MockTokenEndpointProperties.PROPERTIE_ENABLE, havingValue = "true", matchIfMissing = true)
public class MockTokenEndpointAutoConfiguration {

    private final ResourceServerProperties resource;

    public MockTokenEndpointAutoConfiguration(ResourceServerProperties resource) {
        this.resource = resource;
    }

    @Bean
    public MockTokenEndpointResourceServerConfigurer mockTokenGranterResourceServerConfigurer(
            @Autowired MockTokenEndpointProperties mockTokenEndpointProperties,
            @Autowired AuthorizationServerEndpointsConfiguration endpoints
    ) throws Exception {
        MockTokenEndpointResourceServerConfigurer resourceServerConfigurer = new MockTokenEndpointResourceServerConfigurer();
        resourceServerConfigurer.setOrder(mockTokenEndpointProperties.getOrder());
        resourceServerConfigurer.setAccess(mockTokenEndpointProperties.getAccess());
        resourceServerConfigurer.setHandlerMapping(endpoints.oauth2EndpointHandlerMapping());
        resourceServerConfigurer.setResourceId(resource.getId());
        return resourceServerConfigurer;
    }

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
