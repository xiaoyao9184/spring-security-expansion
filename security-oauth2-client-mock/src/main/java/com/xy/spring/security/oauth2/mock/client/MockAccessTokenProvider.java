package com.xy.spring.security.oauth2.mock.client;

import com.xy.spring.security.oauth2.mock.MockTokenGranter;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Iterator;
import java.util.List;

/**
 * Created by xiaoyao9184 on 2018/7/31.
 */
public class MockAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

    private MultiValueMap<String, String> getParametersForTokenRequest(MockResourceDetails resource, AccessTokenRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.set("grant_type", MockTokenGranter.GRANT_TYPE);
        form.putAll(request);
        if (!form.containsKey("username")) {
            throw new UsernameRequiredException();
        }

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

    @Override
    public OAuth2AccessToken obtainAccessToken(
            OAuth2ProtectedResourceDetails details,
            AccessTokenRequest request) throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException {
        MockResourceDetails resource = (MockResourceDetails) details;
        return retrieveToken(request, resource, getParametersForTokenRequest(resource, request), new HttpHeaders());
    }

    @Override
    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof MockResourceDetails && "mock".equals(resource.getGrantType());
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(
            OAuth2ProtectedResourceDetails resource,
            OAuth2RefreshToken refreshToken,
            AccessTokenRequest request) throws UserRedirectRequiredException {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken.getValue());
        return retrieveToken(request, resource, form, new HttpHeaders());
    }

    @Override
    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
        return supportsResource(resource);
    }
}
