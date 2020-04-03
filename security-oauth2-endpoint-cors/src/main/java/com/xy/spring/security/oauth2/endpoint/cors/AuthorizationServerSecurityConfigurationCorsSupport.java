package com.xy.spring.security.oauth2.endpoint.cors;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

@Configuration
public class AuthorizationServerSecurityConfigurationCorsSupport
        implements BeanPostProcessor {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerSecurityConfigurationCorsSupport.class);

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof AuthorizationServerSecurityConfiguration) {
            ProxyFactory factory = new ProxyFactory();
            factory.setTarget(bean);
            factory.addAdvice(new TokenEndpointOptionsPermitSupportCorsAdapter());
            bean = factory.getProxy();
        }
        return bean;
    }

    private static class TokenEndpointOptionsPermitSupportCorsAdapter implements MethodInterceptor {

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            Object result = invocation.proceed();
            if (invocation.getMethod().getName().equals("init")) {
                Method method = ReflectionUtils
                        .findMethod(WebSecurityConfigurerAdapter.class, "getHttp");
                ReflectionUtils.makeAccessible(method);

                Object targetObject = invocation.getThis();
                HttpSecurity http = (HttpSecurity) ReflectionUtils.invokeMethod(method,
                        targetObject);

                FrameworkEndpointHandlerMapping handlerMapping =
                        http.getSharedObject(FrameworkEndpointHandlerMapping.class);
                if(handlerMapping == null ||
                        handlerMapping.getCorsConfigurations().size() == 0){
                    logger.warn("{} not set Cors configuration.",
                            FrameworkEndpointHandlerMapping.class.getName());
                }
                addPermitAllOfOptionsMethodForTokenEndpoint(http);
            }
            return result;
        }

        @SuppressWarnings("unchecked")
        private void addPermitAllOfOptionsMethodForTokenEndpoint(HttpSecurity http) throws Exception {
            ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry r =
                    http.getConfigurer(ExpressionUrlAuthorizationConfigurer.class)
                            .getRegistry();
            Field field = ReflectionUtils.findField(ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry.class,"urlMappings");
            ReflectionUtils.makeAccessible(field);
            List<Object> list = (List<Object>) field.get(r);

            http.authorizeRequests()
                    .antMatchers(HttpMethod.OPTIONS,"/oauth/token")
                    .permitAll()
                    .and();

            Object requestMatcher = list.remove(list.size() - 1);
            list.add(0,requestMatcher);
        }
    }

}
