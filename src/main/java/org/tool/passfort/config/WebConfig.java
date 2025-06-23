package org.tool.passfort.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.tool.passfort.interceptor.*;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final JwtAuthenticationInterceptor jwtAuthenticationInterceptor;
    private final PermissionInterceptor permissionInterceptor;
    private final DeviceInfoInterceptor deviceInfoInterceptor;
    private final RateLimitInterceptor rateLimitInterceptor;
    private final RecentlyUsedInterceptor recentlyUsedInterceptor;

    @Autowired
    public WebConfig(JwtAuthenticationInterceptor jwtAuthenticationInterceptor, PermissionInterceptor permissionInterceptor, DeviceInfoInterceptor deviceInfoInterceptor, RateLimitInterceptor rateLimitInterceptor, RecentlyUsedInterceptor recentlyUsedInterceptor) {
        this.jwtAuthenticationInterceptor = jwtAuthenticationInterceptor;
        this.permissionInterceptor = permissionInterceptor;
        this.deviceInfoInterceptor = deviceInfoInterceptor;
        this.rateLimitInterceptor = rateLimitInterceptor;
        this.recentlyUsedInterceptor = recentlyUsedInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        /* 添加设备信息拦截器 */
        registry.addInterceptor(deviceInfoInterceptor)
                .addPathPatterns("/**"); // 拦截所有后端 API 请求

        /* 请求频率限制拦截器 */
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/**"); // 对所有后端 API 进行频率限制

        /* 添加 JWT 验证拦截器 */
        String[] jwtExcludedPaths = {
                "/index.html", //后端首页
                "/user/login", //登录
                "/user/register", //注册
                "/user/verify/*", // 用户身份验证
                "/user/reset_password", // 重置密码
                "/user/new_access_token",  //获取新的 access token
                "/user/new_refresh_token",  //获取新的 refresh token
                "/user/refresh_token_expiring_soon", //查询 refresh token 是否即将过期
                "/mail/register_verify", // 注册的邮箱验证
                "/mail/verify" // 邮箱验证
        };

        registry.addInterceptor(jwtAuthenticationInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(jwtExcludedPaths);

        String permissionExcludedPaths[] = {
                "/user/**",  //用户相关接口
                "/mail/**"  //邮箱相关接口
        };

        // 添加权限控制拦截器
        registry.addInterceptor(permissionInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(permissionExcludedPaths);

        // 添加最近使用凭证拦截器
        registry.addInterceptor(recentlyUsedInterceptor)
                .addPathPatterns("/credential/view")
                .addPathPatterns("/credential/view/qr");
    }
}
