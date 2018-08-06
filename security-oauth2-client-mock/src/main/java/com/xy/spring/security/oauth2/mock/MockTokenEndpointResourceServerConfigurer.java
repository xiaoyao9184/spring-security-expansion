package com.xy.spring.security.oauth2.mock;

import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
public class MockTokenEndpointResourceServerConfigurer extends ResourceServerConfigurerAdapter implements Ordered {

    private FrameworkEndpointHandlerMapping handlerMapping;
    private Integer order;
    private String access;
    private String resourceId;

    public void setHandlerMapping(FrameworkEndpointHandlerMapping handlerMapping) {
        this.handlerMapping = handlerMapping;
    }

    public void setOrder(Integer order) {
        this.order = order;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(resourceId);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
		String mockTokenPath = handlerMapping.getServletPath(MockTokenEndpointProperties.PROPERTIE_ENDPOINT);
        http.requestMatchers()
                    .antMatchers(mockTokenPath)
                    .and()
                .authorizeRequests()
                    .mvcMatchers(mockTokenPath)
                    .access(access)
                    .and()
                ;
        // @formatter:on
    }

    @Override
    public int getOrder() {
        return order;
    }

}
