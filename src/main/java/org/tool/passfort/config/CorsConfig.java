package org.tool.passfort.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer(){
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**") // 允许 /api 路径下的所有请求
                        .allowedOrigins("http://localhost:3000") // 允许所有域名访问
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")  // 允许所有请求方法访问
                        .allowedHeaders("*") // 允许所有请求头访问
                        .allowCredentials(true); // 允许发送Cookie
            }
        };
    }
}
