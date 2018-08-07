package com.xy.sample.security.oauth2.passwrod;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.Base64Utils;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        PasswordClientApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
public class PasswordLoginTest {


    @Autowired
    private MockMvc mvc;

    /**
     * PLS run this after auth-server
     * @throws Exception
     */
    @Test
    public void password_admin_use_client_endpoint()
            throws Exception {

        String clientIdSecret = "password:password";
        String base64 = Base64Utils.encodeToString(clientIdSecret.getBytes("UTF-8"));

        mvc.perform(post("/login/password")
                .content("username=admin&password=admin&grant_type=password")
                .header("Authorization","Basic " + base64)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().is(200))
                .andDo(mvcResult -> {
                    mvc.perform(get("/health")
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().isOk())
                            .andExpect(jsonPath("status").exists());
                });
    }

}
