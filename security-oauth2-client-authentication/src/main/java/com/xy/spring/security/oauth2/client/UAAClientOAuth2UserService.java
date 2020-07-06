package com.xy.spring.security.oauth2.client;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.bind.BindResult;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
public class UAAClientOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private static final String MISSING_CLIENT_INFO_URI_ERROR_CODE = "missing_client_info_uri";

    private static final String MISSING_CLIENT_ID_ATTRIBUTE_ERROR_CODE = "missing_client_id_attribute";

    private static final String INVALID_CLIENT_INFO_RESPONSE_ERROR_CODE = "invalid_client_info_response";

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE =
            new ParameterizedTypeReference<Map<String, Object>>() {};

    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter;

    private RestOperations restOperations;

    private Environment environment;


    public UAAClientOAuth2UserService(Environment environment) {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
        this.environment = environment;
        this.requestEntityConverter = new UAAClientOAuth2UserRequestEntityConverter(environment);
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");

        if(!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(userRequest.getClientRegistration().getAuthorizationGrantType())){
            return null;
        }

        String clientInfoUri = getClientInfoUri(this.environment, userRequest.getClientRegistration());
        if (!StringUtils.hasText(clientInfoUri)) {
            OAuth2Error oauth2Error = new OAuth2Error(
                    MISSING_CLIENT_INFO_URI_ERROR_CODE,
                    "Missing required ClientInfo Uri in UserInfoEndpoint for Client Registration: " +
                            userRequest.getClientRegistration().getRegistrationId(),
                    null
            );
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        String clientIdAttributeName = getClientIdAttributeName(this.environment, userRequest.getClientRegistration());
        if (!StringUtils.hasText(clientIdAttributeName)) {
            OAuth2Error oauth2Error = new OAuth2Error(
                    MISSING_CLIENT_ID_ATTRIBUTE_ERROR_CODE,
                    "Missing required \"client id\" attribute name in UserInfoEndpoint for Client Registration: " +
                            userRequest.getClientRegistration().getRegistrationId(),
                    null
            );
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);

        ResponseEntity<Map<String, Object>> response;
        try {
            response = this.restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error oauth2Error = ex.getError();
            StringBuilder errorDetails = new StringBuilder();
            errorDetails.append("Error details: [");
            errorDetails.append("ClientInfo Uri: ").append(clientInfoUri);
            errorDetails.append(", Error Code: ").append(oauth2Error.getErrorCode());
            if (oauth2Error.getDescription() != null) {
                errorDetails.append(", Error Description: ").append(oauth2Error.getDescription());
            }
            errorDetails.append("]");
            oauth2Error = new OAuth2Error(INVALID_CLIENT_INFO_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the ClientInfo Resource: " + errorDetails.toString(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_CLIENT_INFO_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the ClientInfo Resource: " + ex.getMessage(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        }

        Map<String, Object> userAttributes = response.getBody();
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(userAttributes));
        OAuth2AccessToken token = userRequest.getAccessToken();
        for (String authority : token.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }

        return new DefaultOAuth2User(authorities, userAttributes, clientIdAttributeName);
    }

    /**
     * Sets the {@link Converter} used for converting the {@link OAuth2UserRequest}
     * to a {@link RequestEntity} representation of the ClientInfo Request.
     *
     * @param requestEntityConverter the {@link Converter} used for converting to a {@link RequestEntity} representation of the ClientInfo Request
     */
    public final void setRequestEntityConverter(Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter) {
        Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
        this.requestEntityConverter = requestEntityConverter;
    }

    /**
     * Sets the {@link RestOperations} used when requesting the ClientInfo resource.
     *
     * <p>
     * <b>NOTE:</b> At a minimum, the supplied {@code restOperations} must be configured with the following:
     * <ol>
     *  <li>{@link ResponseErrorHandler} - {@link OAuth2ErrorResponseErrorHandler}</li>
     * </ol>
     *
     * @param restOperations the {@link RestOperations} used when requesting the ClientInfo resource
     */
    public final void setRestOperations(RestOperations restOperations) {
        Assert.notNull(restOperations, "restOperations cannot be null");
        this.restOperations = restOperations;
    }

    /**
     * Sets the {@link Environment} used for dynamic find properties of the ClientInfoUri and ClientIdAttributeName
     * from Spring Security OAuth2 Client Provider properties
     *
     * @param environment the {@link Environment} used for find properties of the ClientInfoUri and ClientIdAttributeName
     */
    public final void setEnvironment(Environment environment) {
        Assert.notNull(environment, "environment cannot be null");
        this.environment = environment;
    }

    private static final String DEFAULT_CLIENT_INFO_URI_SUFFIX = "clientinfo";
    private static final String PATH_DELIMITER = "/";
    private static final String SPRING_SECURITY_OAUTH2_CLIENT_PREFIX = "spring.security.oauth2.client";
    private static final String PROPERTY_DELIMITER = ".";
    private static final String SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_NAME = "provider";
    private static final String CLIENT_INFO_URI_PROPERTY_NAME = "client-info-uri";
    private static final String CLIENT_ID_ATTRIBUTE_PROPERTY_NAME = "client-id-attribute";
    private static final String DEFAULT_CLIENT_ID_ATTRIBUTE_PROPERTY_NAME = "client_id";

    public static String getClientInfoUri(Environment environment, ClientRegistration clientRegistration){
        String registrationId = clientRegistration.getRegistrationId();
        String clientInfoUri = getPropertyFromRegistrationClientProvider(environment, registrationId, CLIENT_INFO_URI_PROPERTY_NAME);
        if(clientInfoUri != null){
            return clientInfoUri;
        }

        String userInfoUri = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();
        List<String> paths = Stream.of(userInfoUri.split(PATH_DELIMITER)).collect(Collectors.toList());
        paths.remove(paths.size() - 1);
        paths.add(DEFAULT_CLIENT_INFO_URI_SUFFIX);
        return String.join(PATH_DELIMITER, paths);
    }

    public static String getClientIdAttributeName(Environment environment, ClientRegistration clientRegistration){
        String registrationId = clientRegistration.getRegistrationId();
        String clientIdAttributeName = getPropertyFromRegistrationClientProvider(environment, registrationId, CLIENT_ID_ATTRIBUTE_PROPERTY_NAME);
        if(clientIdAttributeName != null){
            return clientIdAttributeName;
        }

        return DEFAULT_CLIENT_ID_ATTRIBUTE_PROPERTY_NAME;
    }

    private static String getPropertyFromRegistrationClientProvider(
            Environment environment, String registrationId, String propertyName) {
        if(environment != null){
            BindResult<OAuth2ClientProperties> result = Binder.get(environment)
                    .bind(SPRING_SECURITY_OAUTH2_CLIENT_PREFIX, OAuth2ClientProperties.class);
            if (result.isBound()) {
                String providerId = Optional.of(result)
                        .map(BindResult::get)
                        .map(OAuth2ClientProperties::getRegistration)
                        .map(map -> map.get(registrationId))
                        .map(OAuth2ClientProperties.Registration::getProvider)
                        .orElse(registrationId);

                String propertyFullName = String.join(PROPERTY_DELIMITER,
                        SPRING_SECURITY_OAUTH2_CLIENT_PREFIX,
                        SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_NAME,
                        providerId,
                        propertyName);

                return environment.getProperty(propertyFullName);
            }
        }
        return null;
    }

}
