package com.xy.spring.security.oauth2.client;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by xiaoyao9184 on 2020/6/21.
 */
public class OAuth2ErrorRefererRequestMatcher implements RequestMatcher {

    private final String authorizationRequestBaseUri;
    private final AntPathMatcher matcher;

    public OAuth2ErrorRefererRequestMatcher(String authorizationRequestBaseUri) {
        this.authorizationRequestBaseUri = authorizationRequestBaseUri;
        this.matcher = new AntPathMatcher();
        matcher.setCaseSensitive(true);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String referer = request.getHeader(HttpHeaders.REFERER);
        if(referer == null){
            return false;
        }

        MultiValueMap<String, String> params = OAuth2AuthorizationRequestUtils.toMultiMap(request.getParameterMap());

        String authorizationRequestUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .path(this.authorizationRequestBaseUri)
                .build()
                .toUriString();

        return params.containsKey(OAuth2ParameterNames.ERROR) &&
                matcher.match(authorizationRequestUri,referer);
    }

    @Override
    public String toString() {
        return "OAuth2ErrorRequestMatcher [expected error param by referer=" + authorizationRequestBaseUri + "]";
    }

}
