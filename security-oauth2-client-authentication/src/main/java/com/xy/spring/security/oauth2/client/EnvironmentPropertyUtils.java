package com.xy.spring.security.oauth2.client;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.bind.BindResult;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
public class EnvironmentPropertyUtils {

    private static final String DEFAULT_CLIENT_INFO_URI_SUFFIX = "clientinfo";
    private static final String PATH_DELIMITER = "/";
    private static final String SPRING_SECURITY_OAUTH2_CLIENT_PREFIX = "spring.security.oauth2.client";
    private static final String PROPERTY_DELIMITER = ".";
    private static final String SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_NAME = "provider";
    private static final String SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_NAME = "registration";
    private static final String CLIENT_INFO_URI_PROPERTY_NAME = "client-info-uri";
    private static final String CLIENT_ID_ATTRIBUTE_PROPERTY_NAME = "client-id-attribute";
    private static final String DEFAULT_CLIENT_ID_ATTRIBUTE_PROPERTY_NAME = "client_id";

    private static final String CLIENT_USER_AUTHORITY = "authority";

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


    public static String getClientUserAuthority(Environment environment, ClientRegistration clientRegistration){
        String registrationId = clientRegistration.getRegistrationId();
        return getPropertyFromRegistrationClient(environment, registrationId, CLIENT_USER_AUTHORITY);
    }

    public static String getPropertyFromRegistrationClient(
            Environment environment, String registrationId, String propertyName) {
        if(environment != null){
            BindResult<OAuth2ClientProperties> result = Binder.get(environment)
                    .bind(SPRING_SECURITY_OAUTH2_CLIENT_PREFIX, OAuth2ClientProperties.class);
            if (result.isBound()) {
                String propertyFullName = String.join(PROPERTY_DELIMITER,
                        SPRING_SECURITY_OAUTH2_CLIENT_PREFIX,
                        SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_NAME,
                        registrationId,
                        propertyName);

                return environment.getProperty(propertyFullName);
            }
        }
        return null;
    }
}
