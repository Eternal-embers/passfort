package org.tool.passfort.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.tool.passfort.interceptor.JwtAuthenticationInterceptor;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final JwtAuthenticationInterceptor jwtAuthenticationInterceptor;

    @Autowired
    public WebConfig(JwtAuthenticationInterceptor jwtAuthenticationInterceptor) {
        this.jwtAuthenticationInterceptor = jwtAuthenticationInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        String[] excludedPaths = {
                "/index.html", //后端首页
                "/api/user/login", //登录
                "/api/user/register", //注册
                "/api/user/activate", //激活帐号
                "/api/user/logout", //注销登录
                "/api/user/new_access_token",  //获取新的 access token
                "/api/user/new_refresh_token",  //获取新的 refresh token
                "/api/user/refresh_token_expiring_soon", //查询 refresh token 是否即将过期
                "/api/email/verify" // 邮箱验证
        };

        registry.addInterceptor(jwtAuthenticationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(excludedPaths);
    }
}
