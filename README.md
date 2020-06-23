# spring-security-expansion

[![](https://jitpack.io/v/xiaoyao9184/spring-security-expansion.svg)](https://jitpack.io/#xiaoyao9184/spring-security-expansion)

XY's spring security expansion


# info




## security-oauth2-client-mock

Grant type 'Mock' is very similar to OAuth2 'Resource Owner Credentials Grant Flow'
without password. So dangerous but flexible. 

- Simulate user login troubleshooting in the actual system
- Docking other authentication systems like CAS

You can use it on a authentication server in two ways.

1. Send mock info to token endpoint: '/oauth/token'

    【Client】POST ▶ 【Token Endpoint】 with client authorization header
    
    | param | required | value |
    |:-----:|:-----:|:-----:|
    | grant_type | yes | mock |
    | username| yes| resource owner username |
    | scope| no | access range |

2. Send mock info to mock(oauth resource) endpoint: '/oauth/token/mock'
                        
    【Client】POST ▶ 【Mock Endpoint】 with ```access token header```

    | param | required | value |
    |:-----:|:-----:|:-----:|
    | username| yes| resource owner username |
    | scope| no | access range |

Note. if you use NO.2 you must make sure token has 'DEV' authority. 
The default of this endpoint allows God(Developer) to access.


And you can use it on a client with 'OAuth2RestTemplate'

Supplement example later.


## security-oauth2-client-password

Use custom login in the gateway with 'EnableOAuth2Sso'

We know that the default 'EnableOAuth2Sso' uses the 'Authorization Code Grant Flow' to login.
So the redirect page is a must. and some time we need customize the login page.

Three various ways can be done

1. The authentication server supports different styles page with different client.
2. Embed a minimal page from the authentication server using an iframe, usually containing only the username and password and the confirmation button.
3. Client self support login.

This project is the realization of NO.3.

You can use it on a gateway client.

【Client】POST ▶ 【Login Endpoint】 without any header

| param | required | value |
|:-----:|:-----:|:-----:|
| username| yes| resource owner username |
| password| yes| resource owner password |
| scope| no | access range |

Too similar to 'Resource Owner Credentials Grant Flow',
it will not response any TOKEN, but login process has been completed in the background.



## security-oauth2-client-authentication

Upgrade RegisteredOAuth2AuthorizedClient for authorization

In security 5 support multiple client authorization, you can use these tokens later.
But has nothing to do with the host project, exception when you use `oauth2Login` DSL,
`oauth2Login` DSL upgrade authorized client token to be the host authorization,
to support single sign-on (now called OAuth2Login)

With this project you will be able to use the following grant method to support OAuth login

| grant | support | by |
|:-----:|:-----:|:-----:|
| authorization_code | yes | spring security |
| implicit | no | spring security |
| password | yes | this project |
| client-credentials | no | this project |

#### principle

`oauth2Login` use `OAuth2AuthorizationRequestRedirectFilter` and `OAuth2LoginAuthenticationFilter`
`oauth2Client` use `OAuth2AuthorizationRequestRedirectFilter` and `OAuth2AuthorizationCodeGrantFilter`

When you visit `/oauth2/authorization/{registrationId}` will be intercepted by `OAuth2AuthorizationRequestRedirectFilter` 
redirect to oauth2 auth server, after the auth server is authorized, it will return to an endpoint by configuration.
If intercepted by `OAuth2AuthorizationCodeGrantFilter`, will complete the `authorization_code` process to get the token,
and hold in OAuth2AuthorizedClientRepository.
If intercepted by `OAuth2LoginAuthenticationFilter`, will complete the `authorization_code` process to get the token and
`user-info-uri` to get user information, then upgrade it for attempt authentication.

That means that `oauth2Login` performed 2 steps, authorization client and upgrade authorized client for attempt authentication.
`oauth2Client` only authorization client, only support `authorization_code` flow.

So `OAuth2ClientAuthorizedConfigurer` support separate two steps, 
 - upgrade authorized client for attempt authentication by `OAuth2ClientAuthorizedAuthenticationFilter`.
 - authorization client by `OAuth2PasswordGrantFilter`

#### used

You can use password grant login flow

- authorization client use password 
- upgrade password type authorized client attempt authentication

1. Config WebSecurityConfigurerAdapter

    ```java
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            //noinspection unchecked
            http.apply(new OAuth2ClientAuthorizedConfigurer());
            http.oauth2Client();
            http.oauth2Login();
        }
    ```
    Make sure apply `OAuth2ClientAuthorizedConfigurer` with enable `oauth2Client`

2. Config security properties

    ```yaml
    spring:
      security:
        oauth2:
          client:
            registration:
              uaa-password:
                provider: uaa
                client-id: spring-security-expansion-sample
                client-secret: sample
                authorization-grant-type: password
                redirect-uri: "{baseUrl}/login/oauth2/client/{registrationId}"
              uaa-authorization-code:
                provider: uaa
                client-id: spring-security-expansion-sample
                client-secret: sample
                authorization-grant-type: authorization_code
                redirect-uri: "{baseUrl}/login/oauth2/client/{registrationId}"
              uaa-sso:
                provider: uaa
                client-id: spring-security-expansion-sample
                client-secret: sample
                authorization-grant-type: authorization_code
                redirect-uri: "{baseUrl}/login/oauth2/code/"
            provider:
              uaa:
                authorization-uri: http://ds1019plus:16666/oauth/authorize
                token-uri: http://ds1019plus:16666/oauth/token
                user-info-uri: http://ds1019plus:16666/userinfo
                user-name-attribute: user_name
    ```
    Set `authorization-grant-type` to be `password`
    Set `redirect-uri` to be `"{baseUrl}/login/oauth2/client/{registrationId}"`

3. Run and login

    【Client】POST FormData ▶ 【Login Endpoint】 without those params
    
    | param | required | value |
    |:-----:|:-----:|:-----:|
    | username | yes | resource owner username |
    | password | yes | resource owner password |
    
    Default 【Login Endpoint】is `/oauth2/authorization/{registrationId}`,
    and registration id is a `password` `authorization-grant-type` in this case is `uaa-password`
    
    If successful will redirect two times,
    First time will redirect to `/login/oauth2/client/{registrationId}`
    in this case is `/login/oauth2/client/uaa-password`.
    Second time will redirect to `/`.
    
    If fails redirect still happens,
    First time will redirect to `/login/oauth2/client/{registrationId}` with error params.
    Then response 401 or 500 without redirect.