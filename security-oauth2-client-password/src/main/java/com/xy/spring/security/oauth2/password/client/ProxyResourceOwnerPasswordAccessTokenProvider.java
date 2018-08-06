package com.xy.spring.security.oauth2.password.client;

import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Iterator;
import java.util.List;

/**
 * Created by xiaoyao9184 on 2018/7/31.
 */
public class ProxyResourceOwnerPasswordAccessTokenProvider extends ResourceOwnerPasswordAccessTokenProvider implements AccessTokenProvider {


    @Override
    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof ProxyResourceOwnerPasswordResourceDetails && "password".equals(resource.getGrantType());
    }

    @Override
    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
            throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {
        ProxyResourceOwnerPasswordResourceDetails resource = (ProxyResourceOwnerPasswordResourceDetails) details;
        return retrieveToken(request, resource, getParametersForTokenRequest(resource, request), new HttpHeaders());
    }


    private MultiValueMap<String, String> getParametersForTokenRequest(ProxyResourceOwnerPasswordResourceDetails resource, AccessTokenRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.set("grant_type", "password");

        form.set("username", request.get("username").toString());
        form.set("password", request.get("password").toString());
        form.putAll(request);

        if (resource.isScoped()) {

            StringBuilder builder = new StringBuilder();
            List<String> scope = resource.getScope();

            if (scope != null) {
                Iterator<String> scopeIt = scope.iterator();
                while (scopeIt.hasNext()) {
                    builder.append(scopeIt.next());
                    if (scopeIt.hasNext()) {
                        builder.append(' ');
                    }
                }
            }

            form.set("scope", builder.toString());
        }

        return form;

    }
}
