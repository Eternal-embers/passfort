package org.tool.passfort.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.tool.passfort.util.secure.PasswordHasher;
import org.tool.passfort.util.secure.impl.*;

@Configuration
public class PasswordHasherConfig {
    @Bean
    @Primary
    public PasswordHasher PBKDF2PasswordHasher() {
        return new PBKDF2PasswordHasher();
    }

    /**
     * 可以选择其他加密方式，但必须总是使用固定的一种方式来加密
     * 如果需要使用以下加密方式，请将它作为 PasswordHasher 的实现类Bean
    @Bean
    public PasswordHasher Argon2PasswordHasher(){
        return new Argon2PasswordHasher();
    }

    @Bean
    public PasswordHasher BcryptPasswordHasher(){
        return new BcryptPasswordHasher();
    }

    @Bean
    public PasswordHasher ScryptPasswordHasher(){
        return new ScryptPasswordHasher();
    }

    @Bean
    public PasswordHasher SHA3PasswordHasher(){
        return new SHA3PasswordHasher();
    }
    **/
}