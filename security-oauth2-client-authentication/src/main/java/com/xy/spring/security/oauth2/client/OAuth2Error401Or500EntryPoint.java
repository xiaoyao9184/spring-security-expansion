package com.xy.spring.security.oauth2.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by xiaoyao9184 on 2020/6/21.
 */
public class OAuth2Error401Or500EntryPoint implements AuthenticationEntryPoint {
    private static final Log logger = LogFactory.getLog(OAuth2Error401Or500EntryPoint.class);

    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        if(authException instanceof OAuth2AuthenticationException) {
            OAuth2AuthenticationException iae = (OAuth2AuthenticationException) authException;
            if (INVALID_TOKEN_RESPONSE_ERROR_CODE.equals(iae.getError().getErrorCode())) {
                if (logger.isDebugEnabled()) {
                    logger.debug("An OAuth2Error with request. Rejecting access");
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
                return;
            }
        }
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, authException.getMessage());
    }

}
