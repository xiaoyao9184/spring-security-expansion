package com.xy.sample.security.oauth2.client;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.core.StringContains.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by xiaoyao9184 on 2020/7/5.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        ImplicitAuthenticationApplication.class
})
@SpringBootTest
@AutoConfigureMockMvc
public class ImplicitLoginTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void authorization_use_implicit()
            throws Exception {
        //authorization client
        mvc.perform(get("/oauth2/authorization/uaa-implicit"))
                .andExpect(status().is(302))
                .andExpect(header().string(HttpHeaders.LOCATION, containsString("redirect_uri=http://localhost/implicit.html")))
                .andDo(mvcResult -> {
                    //mock front end sends tokens to the back end
                    mvc.perform(post("/login/oauth2/client/uaa-implicit?")
                            .content("token_type=bearer&access_token=fake_value&expires_in=1000&scope=read+write&registration_id=uaa-implicit")
                            .session((MockHttpSession) mvcResult.getRequest().getSession()))
                            .andExpect(status().is(302))
                            .andExpect(header().string(HttpHeaders.LOCATION,"http://localhost/login/oauth2/client/uaa-implicit"))
                            .andDo(mvcResult2 -> {
                                //TODO check client authorization is correct
                                //Can't promote authorization because it's a fake token
                            });
                });
    }

}
