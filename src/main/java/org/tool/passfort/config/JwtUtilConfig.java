package org.tool.passfort.config;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.tool.passfort.util.jwt.JwtUtil;

@Configuration
public class JwtUtilConfig {
    @Value("${jwt.secret}")
    private String secret;//密钥

    @Value("${jwt.issuer}")
    private String issuer;//签发者

    @Value("${jwt.audience}")
    private String audience;//接收者

    @Bean
    public JwtUtil jwtUtil() {
        Algorithm algorithm = Algorithm.HMAC512(secret);
        return new JwtUtil(issuer, audience, algorithm);
    }
}
