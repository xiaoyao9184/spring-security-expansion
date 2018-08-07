package com.xy.sample.security.oauth2.password;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

/**
 * Created by xiaoyao9184 on 2018/8/6.
 */
@Controller
public class OAuthUserMvcController {

    @RequestMapping(value = "/user",method = RequestMethod.GET)
    @ResponseBody
    public Principal user(Principal user) {
        return user;
    }

}
