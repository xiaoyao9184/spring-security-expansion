package com.xy.spring.security.oauth2.mock.client;

/**
 * Created by xiaoyao9184 on 2018/7/31.
 */
public class UsernameRequiredException extends RuntimeException {

	public UsernameRequiredException() {
		super("A mock is required to get the users name");
	}

}
