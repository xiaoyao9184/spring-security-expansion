package com.xy.spring.security.oauth2.client;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by xiaoyao9184 on 2020/6/21.
 */
public class OAuth2ErrorResolver {

    public OAuth2Error resolve(HttpServletRequest request){
        MultiValueMap<String, String> params = OAuth2AuthorizationRequestUtils.toMultiMap(request.getParameterMap());
        if(params.containsKey(OAuth2ParameterNames.ERROR)){
            String error = params.getFirst(OAuth2ParameterNames.ERROR);
            String error_description = params.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
            String error_uri = params.getFirst(OAuth2ParameterNames.ERROR_URI);
            return new OAuth2Error(error,
                    error_description, error_uri);
        }
        return null;
    }
}
