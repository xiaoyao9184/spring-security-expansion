package com.xy.sample.security.oauth2.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.lang.reflect.Field;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        ClientAuthenticationApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
public class ClientLoginTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void authorization_use_client()
            throws Exception {
        //authorization client
        mvc.perform(get("/oauth2/authorization/uaa-client"))
                .andExpect(status().is(302))
                .andExpect(header().string(HttpHeaders.LOCATION,"http://localhost/login/oauth2/client/uaa-client"))
                .andDo(mvcResult -> {
                    //mock browser redirect
                    //use client authorization for login
                    mvc.perform(get("/login/oauth2/client/uaa-client")
                            .header(HttpHeaders.REFERER,mvcResult.getRequest().getRequestURL().toString())
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().is(302))
                            .andExpect(header().string(HttpHeaders.LOCATION,"/"))
                            .andDo(mvcResult2 -> {
                                mvc.perform(get("/user")
                                        .session((MockHttpSession) mvcResult.getRequest().getSession()))
                                        .andExpect(status().isOk())
                                        .andExpect(jsonPath("name").exists())
                                        .andExpect(jsonPath("client-registration-id",equalTo("uaa-client")));
                            });
                });
    }

    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;

    @Test
    public void authorization_error_use_client()
            throws Exception {
        ClientRegistration cr = clientRegistrationRepository.findByRegistrationId("uaa-client");
        Field field = ReflectionUtils.findField(ClientRegistration.class,"clientSecret");
        field.setAccessible(true);
        ReflectionUtils.setField(field, cr, "error");
        //authorization client
        mvc.perform(post("/oauth2/authorization/uaa-client"))
                .andExpect(status().is(302))
                .andExpect(header().string(HttpHeaders.LOCATION,startsWith("http://localhost/login/oauth2/client/uaa-client")))
                .andDo(mvcResult -> {
                    String errorParams = UriComponentsBuilder.fromUriString(mvcResult.getResponse().getRedirectedUrl())
                        .build().getQuery();
                    //mock non-browser access without referer header
                    mvc.perform(get("/login/oauth2/client/uaa-client?" + errorParams)
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().is(302))
                            .andExpect(header().string(HttpHeaders.LOCATION,containsString("/login?error")));

                    //mock browser redirect access with referer header
                    mvc.perform(get("/login/oauth2/client/uaa-client?" + errorParams)
                            .header(HttpHeaders.REFERER,mvcResult.getRequest().getRequestURL().toString())
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().is(401));
                });
    }

}
