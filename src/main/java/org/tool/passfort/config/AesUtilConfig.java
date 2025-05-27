package org.tool.passfort.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.tool.passfort.util.encrypt.AesUtil;

@Configuration
public class AesUtilConfig {
    @Bean
    public AesUtil aesUtil(){
        return new AesUtil();
    }
}
