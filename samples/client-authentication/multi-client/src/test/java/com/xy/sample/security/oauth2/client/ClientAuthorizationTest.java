package com.xy.sample.security.oauth2.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Created by xiaoyao9184 on 2020/6/20.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        ClientAuthenticationApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
public class ClientAuthorizationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void authorization_use_password()
            throws Exception {
        //authorization client
        mvc.perform(post("/oauth2/authorization/uaa-password")
                .content("username=admin&password=admin&grant_type=password")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().is(302))
                .andExpect(header().string(HttpHeaders.LOCATION,"http://localhost/login/oauth2/client/uaa-password"))
                .andDo(mvcResult -> {
                    //use client authorization for login
                    mvc.perform(get("/login/oauth2/client/uaa-password")
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().is(302))
                            .andExpect(header().string(HttpHeaders.LOCATION,"/"))
                            .andDo(mvcResult2 -> {
                                mvc.perform(get("/user")
                                        .session((MockHttpSession) mvcResult.getRequest().getSession()))
                                        .andExpect(status().isOk())
                                        .andExpect(jsonPath("name").exists())
                                        .andExpect(jsonPath("client-registration-id",equalTo("uaa-password")));
                            });
                });
    }

}
