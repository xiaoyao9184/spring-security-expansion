package com.xy.sample.security.oauth2.password;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {


    @Bean
    public DefaultUserApprovalHandler defaultUserApprovalHandler(){
        return new DefaultUserApprovalHandler();
    }


    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private UserApprovalHandler userApprovalHandler;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("password")
                .secret("password")
                .resourceIds("auth/resource")
                .authorizedGrantTypes("password")
                .scopes("read", "write")
                .and();
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //fix DefaultTokenServices not use ClientDetailsServiceConfigurer's
        DefaultTokenServices defaultTokenServices = (DefaultTokenServices) endpoints.getDefaultAuthorizationServerTokenServices();
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        endpoints
                .userApprovalHandler(userApprovalHandler)
                .authenticationManager(authenticationManager);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.realm("auth/server")
                .checkTokenAccess("isAuthenticated()");
    }

}
