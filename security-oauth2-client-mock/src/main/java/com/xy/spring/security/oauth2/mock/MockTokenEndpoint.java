package com.xy.spring.security.oauth2.mock;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.Map;

/**
 * Created by xiaoyao9184 on 2017/2/20.
 */
@FrameworkEndpoint
public class MockTokenEndpoint {

    private String clientId;
    private String clientSecret;
    private TokenEndpoint tokenEndpoint;


    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setTokenEndpoint(TokenEndpoint tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    @RequestMapping(value = MockTokenEndpointProperties.PROPERTIE_ENDPOINT, method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<OAuth2AccessToken> mock(
            @RequestParam Map<String, String> parameters) throws Exception {
        if(!parameters.containsKey("grant_type")){
            parameters.put("grant_type",MockTokenGranter.GRANT_TYPE);
        }
        User user = new User(clientId, clientSecret, new ArrayList<>());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user,null, new ArrayList<>());
        return tokenEndpoint.postAccessToken(token, parameters);
    }

}
