package com.xy.spring.security.oauth2.client;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
public class OAuth2PasswordLoginPageGeneratingFilter extends GenericFilterBean {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final AntPathRequestMatcher authorizationRequestMatcher;
    private final UriComponentsBuilder authenticationUriComponentsBuilder;

    public OAuth2PasswordLoginPageGeneratingFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                   OAuth2AuthorizedClientRepository authorizedClientRepository,
                                                   String authorizationRequestBaseUri) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        Assert.notNull(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be null");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
        this.authenticationUriComponentsBuilder = UriComponentsBuilder.fromPath(authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (isPasswordLoginUrlRequest(request)) {
            String registrationId = resolveRegistrationId(request);
            ClientRegistration cr = this.clientRegistrationRepository.findByRegistrationId(registrationId);
            boolean isAuthorized = this.isAuthorized(registrationId,request);
            String authenticationUrl = this.authenticationUriComponentsBuilder.buildAndExpand(registrationId).getPath();

            String loginPageHtml = generateLoginPageHtml(request, isAuthorized, cr.getClientName(), authenticationUrl);
            response.setContentType("text/html;charset=UTF-8");
            response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
            response.getWriter().write(loginPageHtml);

            return;
        }

        chain.doFilter(request, response);
    }

    private boolean isAuthorized(String registrationId, HttpServletRequest request) {
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository.loadAuthorizedClient(registrationId, currentAuthentication, request);
        return authorizedClient != null;
    }

    private boolean isPasswordLoginUrlRequest(HttpServletRequest request) {
        return Optional.of(request)
                .map(this::resolveRegistrationId)
                .map(this.clientRegistrationRepository::findByRegistrationId)
                .filter(cr -> AuthorizationGrantType.PASSWORD.equals(cr.getAuthorizationGrantType()))
                .filter(cr -> {
                    MultiValueMap<String, String> params = OAuth2AuthorizationRequestUtils.toMultiMap(request.getParameterMap());
                    return !OAuth2AuthorizationRequestUtils.isPasswordRequest(params);
                })
                .isPresent();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher
                    .matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }

    private String generateLoginPageHtml(
            HttpServletRequest request, boolean isAuthorized, String clientName, String authenticationUrl) {
        StringBuilder sb = new StringBuilder();

        sb.append("<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n"
                + "  <head>\n"
                + "    <meta charset=\"utf-8\">\n"
                + "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
                + "    <meta name=\"description\" content=\"\">\n"
                + "    <meta name=\"author\" content=\"\">\n"
                + "    <title>Please sign in</title>\n"
                + "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
                + "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
                + "  </head>\n"
                + "  <body>\n"
                + "     <div class=\"container\">\n");

        String contextPath = request.getContextPath();

        sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath + authenticationUrl + "\">\n"
                + "        <h2 class=\"form-signin-heading\">Please sign in with client " + clientName + "</h2>\n"
                + createAlreadyAuthorized(isAuthorized)
                + "        <p>\n"
                + "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
                + "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
                + "        </p>\n"
                + "        <p>\n"
                + "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
                + "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
                + "        </p>\n"
                + "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
                + "      </form>\n");

        sb.append("</div>\n");
        sb.append("</body></html>");

        return sb.toString();
    }

    private static String createAlreadyAuthorized(boolean isAuthorized) {
        return isAuthorized ? "<div class=\"alert alert-success\" role=\"alert\">You have been already signed in with this client</div>" : "";
    }
}
