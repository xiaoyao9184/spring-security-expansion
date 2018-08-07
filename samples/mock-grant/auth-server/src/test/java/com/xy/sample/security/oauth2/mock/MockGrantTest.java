package com.xy.sample.security.oauth2.mock;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.Base64Utils;

import java.util.HashMap;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        MockServerApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
public class MockGrantTest {


    @Autowired
    private MockMvc mvc;

    @Test
    public void mock_dev_use_token_endpoint()
            throws Exception {

        String clientIdSecret = "mock:mock";
        String base64 = Base64Utils.encodeToString(clientIdSecret.getBytes("UTF-8"));

        mvc.perform(post("/oauth/token")
                .header("Authorization","Basic " + base64)
                .content("username=dev&grant_type=mock")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(jsonPath("access_token").exists());
    }


    @Test
    public void mock_admin_use_mock_endpoint()
            throws Exception {

        String clientIdSecret = "mock:mock";
        String base64 = Base64Utils.encodeToString(clientIdSecret.getBytes("UTF-8"));

        mvc.perform(post("/oauth/token")
                .header("Authorization","Basic " + base64)
                .content("username=dev&grant_type=mock")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(jsonPath("access_token").exists())
                .andDo(mvcResult -> {
                    String json = mvcResult.getResponse().getContentAsString();
                    HashMap map = new ObjectMapper().readValue(json,HashMap.class);
                    String token = (String) map.get("access_token");

                    mvc.perform(post("/oauth/token/mock")
                            .header("Authorization","bearer " + token)
                            .content("username=admin")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                            .andExpect(status().isOk())
                            .andExpect(content()
                                    .contentTypeCompatibleWith(MediaType.APPLICATION_JSON_UTF8))
                            .andExpect(jsonPath("access_token").exists());
                });
    }

}
