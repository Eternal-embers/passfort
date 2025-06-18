package org.tool.passfort.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.tool.passfort.interceptor.JwtAuthenticationInterceptor;
import org.tool.passfort.interceptor.PermissionInterceptor;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final JwtAuthenticationInterceptor jwtAuthenticationInterceptor;
    private final PermissionInterceptor permissionInterceptor;

    @Autowired
    public WebConfig(JwtAuthenticationInterceptor jwtAuthenticationInterceptor, PermissionInterceptor permissionInterceptor) {
        this.jwtAuthenticationInterceptor = jwtAuthenticationInterceptor;
        this.permissionInterceptor = permissionInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        String[] jwtExcludedPaths = {
                "/index.html", //后端首页
                "/api/user/login", //登录
                "/api/user/register", //注册
                "/api/user/verify/*", // 用户身份验证
                "/api/user/reset_password", // 重置密码
                "/api/user/new_access_token",  //获取新的 access token
                "/api/user/new_refresh_token",  //获取新的 refresh token
                "/api/user/refresh_token_expiring_soon", //查询 refresh token 是否即将过期
                "/api/mail/verify" // 邮箱验证
        };

        // 添加 JWT 验证拦截器
        registry.addInterceptor(jwtAuthenticationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(jwtExcludedPaths);

        String permissionExcludedPaths[] = {
                "/api/user/**",  //用户相关接口
                "/api/mail/**"  //邮箱相关接口
        };

        // 添加权限控制拦截器
        registry.addInterceptor(permissionInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(permissionExcludedPaths);
    }
}
