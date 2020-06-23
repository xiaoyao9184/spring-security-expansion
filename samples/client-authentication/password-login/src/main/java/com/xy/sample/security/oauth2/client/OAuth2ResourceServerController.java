package com.xy.sample.security.oauth2.client;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
@RestController
public class OAuth2ResourceServerController {

    @RequestMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2AuthenticationToken token) {
        return new HashMap<String, Object>(){{
            put("name", token.getPrincipal().getName());
            put("client-registration-id",token.getAuthorizedClientRegistrationId());
        }};
    }
}
