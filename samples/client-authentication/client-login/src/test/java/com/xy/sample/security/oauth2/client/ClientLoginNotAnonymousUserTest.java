package com.xy.sample.security.oauth2.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by xiaoyao9184 on 2020/7/3.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        ClientAuthenticationApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.security.oauth2.client.registration.uaa-client.authority=ROLE_DEV")
public class ClientLoginNotAnonymousUserTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void authorization_anonymous()
            throws Exception {
        //authorization client
        mvc.perform(get("/oauth2/authorization/uaa-client"))
                .andExpect(status().is(500));
    }

    @Test
    public void authorization_not_anonymous()
            throws Exception {
        //authorization client
        mvc.perform(get("/user_basic")
                .header("Authorization","Basic ZGV2OmRldg"))
                .andExpect(status().is(200))
                .andDo(mvcResult -> {
                    mvc.perform(get("/oauth2/authorization/uaa-client")
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().is(302))
                            .andExpect(header().string(HttpHeaders.LOCATION,"http://localhost/login/oauth2/client/uaa-client"));
                });
    }

}
