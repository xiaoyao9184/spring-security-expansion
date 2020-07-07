package com.xy.spring.security.oauth2.client;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Copy from {@link import org.springframework.security.oauth2.client.web.OAuth2AuthorizationResponseUtils}
 * Created by xiaoyao9184 on 2020/6/20.
 */
public class OAuth2AuthorizationRequestUtils {

    static MultiValueMap<String, String> toMultiMap(Map<String, String[]> map) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>(map.size());
        map.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    params.add(key, value);
                }
            }
        });
        return params;
    }

    static boolean isPasswordRequest(MultiValueMap<String, String> request) {
        return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.PASSWORD)) &&
                StringUtils.hasText(request.getFirst(OAuth2ParameterNames.USERNAME));
    }

    public static String removeUsername(MultiValueMap<String, String> params) {
        return params.remove(OAuth2ParameterNames.USERNAME).get(0);
    }

    public static String removePassword(MultiValueMap<String, String> params) {
        return params.remove(OAuth2ParameterNames.PASSWORD).get(0);
    }

    public static boolean isTokenRequest(MultiValueMap<String, String> request) {
        return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.ACCESS_TOKEN));
    }

    public static String removeAccessToken(MultiValueMap<String, String> params) {
        return params.remove(OAuth2ParameterNames.ACCESS_TOKEN).get(0);
    }

    public static String removeExpiresIn(MultiValueMap<String, String> params) {
        return params.remove(OAuth2ParameterNames.EXPIRES_IN).get(0);
    }

    public static String removeScope(MultiValueMap<String, String> params) {
        return params.remove(OAuth2ParameterNames.SCOPE).get(0);
    }

    public static String removeTokenType(MultiValueMap<String, String> params) {
        return params.remove(OAuth2ParameterNames.TOKEN_TYPE).get(0);
    }

}
