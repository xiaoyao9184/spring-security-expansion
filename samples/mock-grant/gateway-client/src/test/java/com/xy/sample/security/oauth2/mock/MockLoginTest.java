package com.xy.sample.security.oauth2.mock;

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

import javax.servlet.http.Cookie;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        MockClientApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
public class MockLoginTest {


    @Autowired
    private MockMvc mvc;

    /**
     * PLS run this after auth-server
     * @throws Exception
     */
    @Test
    public void mock_dev_use_token_endpoint()
            throws Exception {

        mvc.perform(post("/login")
                .content("username=dev")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().is(302))
                .andDo(mvcResult -> {
                    mvc.perform(get("/health")
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().isOk())
                            .andExpect(jsonPath("status").exists());
                });
    }

}
