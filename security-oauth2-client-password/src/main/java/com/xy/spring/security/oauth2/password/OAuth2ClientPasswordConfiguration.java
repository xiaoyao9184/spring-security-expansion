package com.xy.spring.security.oauth2.password;

import com.xy.spring.security.oauth2.password.util.CglibHelper;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.MergedBeanDefinitionPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

/**
 * Created by xiaoyao9184 on 2018/7/25.
 */
@Configuration
public class OAuth2ClientPasswordConfiguration
        implements ApplicationContextAware, ImportAware, BeanPostProcessor, MergedBeanDefinitionPostProcessor {

    private ApplicationContext applicationContext;
    private Class<?> configType;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        this.configType = ClassUtils.resolveClassName(importMetadata.getClassName(),
                null);
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (this.configType.isAssignableFrom(bean.getClass())
                && bean instanceof WebSecurityConfigurerAdapter) {
            ProxyFactory factory = new ProxyFactory();
            factory.setTarget(bean);
            factory.addAdvice(new OAuth2ClientPasswordAuthenticationSecurityAdapter(this.applicationContext));
            bean = factory.getProxy();
        }
        return bean;
    }

    /**
     * Only for order with
     * @see org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2SsoCustomConfiguration
     * is nonOrderedPostProcessorNames in
     * @see org.springframework.context.support.PostProcessorRegistrationDelegate#registerBeanPostProcessors(ConfigurableListableBeanFactory, AbstractApplicationContext)
     * @param beanDefinition
     * @param beanType
     * @param beanName
     */
    @Override
    public void postProcessMergedBeanDefinition(RootBeanDefinition beanDefinition, Class<?> beanType, String beanName) {
    }


    private static class OAuth2ClientPasswordAuthenticationSecurityAdapter implements MethodInterceptor {

        private OAuth2PasswordSecurityConfigurer configurer;

        OAuth2ClientPasswordAuthenticationSecurityAdapter(ApplicationContext applicationContext) {
            this.configurer = new OAuth2PasswordSecurityConfigurer(applicationContext);
        }

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            if (invocation.getMethod().getName().equals("init")) {
                Method method = ReflectionUtils
                        .findMethod(WebSecurityConfigurerAdapter.class, "getHttp");
                ReflectionUtils.makeAccessible(method);

                //bug for twice proxy, need checkout real target
                //see https://github.com/spring-projects/spring-security/issues/4101
                Object targetObject = new CglibHelper(invocation.getThis()).getTargetObject();
                HttpSecurity http = (HttpSecurity) ReflectionUtils.invokeMethod(method,
                        targetObject);
                this.configurer.configure(http);
            }
            return invocation.proceed();
        }

    }
}
