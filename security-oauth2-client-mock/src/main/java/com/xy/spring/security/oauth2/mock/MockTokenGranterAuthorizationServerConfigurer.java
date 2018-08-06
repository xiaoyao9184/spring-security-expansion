package com.xy.spring.security.oauth2.mock;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
public class MockTokenGranterAuthorizationServerConfigurer
        implements AuthorizationServerConfigurer {

    @Autowired
    private AuthorizationServerTokenServices tokenServices;

    @Autowired
    private AuthenticationManager authenticationManager;

//    @Autowired
//    private ClientDetailsService clientDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenGranter(new TokenGranter() {
            private OAuth2RequestFactory requestFactory = endpoints.getOAuth2RequestFactory();
            private ClientDetailsService clientDetailsService = endpoints.getClientDetailsService();
            private TokenGranter tokenGranter = endpoints.getTokenGranter();
            private CompositeTokenGranter delegate;

            @Override
            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                if (delegate == null) {
                    List<TokenGranter> tokenGranters = new ArrayList<>();
                    tokenGranters.add(tokenGranter);

                    MockTokenGranter socialTokenGranter =
                            new MockTokenGranter(authenticationManager, tokenServices, clientDetailsService, requestFactory);
                    tokenGranters.add(socialTokenGranter);

                    delegate = new CompositeTokenGranter(tokenGranters);
                }
                return delegate.grant(grantType, tokenRequest);
            }
        });
    }

}
