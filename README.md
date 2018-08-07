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