package org.tool.passfort.util.jwt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;

import java.util.HashMap;
import java.util.Map;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtUtilTest {

    private static final String SECRET = "txFKesShx5+gbbL7IT7YLu6ewBfgdRzHVdrxfmkLx4H+tX2tdqpCWTOH4EQQBRmckWuQhhSKTGgw0qZamPGrxQ==";
    private static final String ISSUER = "PassFort";
    private static final String AUDIENCE = "https://localhost/passfort/";
    private static final Algorithm ALGORITHM = Algorithm.HMAC512(SECRET);

    @Test
    public void testJwtUtil() throws JWTVerificationException {
        // 初始化JwtUtil
        JwtUtil jwtUtil = new JwtUtil(ISSUER, AUDIENCE, ALGORITHM);

        // 准备自定义声明
        Map<String, String> claims = new HashMap<>();
        claims.put("email", "passfort@163.com");
        claims.put("tokenType", "refresh");
        claims.put("key", "refreshToken:1:71b16bf8-b014-4808-9ecd-9f698f6f0a44");

        // 测试生成Token
        long startTime = System.nanoTime(); // 使用纳秒级时间测量
        String token = jwtUtil.createToken("subject", claims, 3600); // 设置Token有效期为1小时
        long endTime = System.nanoTime(); // 结束时间
        long duration = (endTime - startTime) / 1_000_000; // 转换为毫秒
        System.out.println("Token: " + token);
        System.out.println("Token byte size: " + token.getBytes().length + " bytes");
        System.out.println("Token generation time: " + duration + " ms");

        // 验证Token
        startTime = System.nanoTime(); // 使用纳秒级时间测量
        DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
        endTime = System.nanoTime(); // 结束时间
        duration = (endTime - startTime) / 1_000_000; // 转换为毫秒
        System.out.println("Token verification time: " + duration + " ms");

        // 验证Token中的声明
        Assertions.assertEquals("subject", decodedJWT.getSubject());
        Assertions.assertEquals(ISSUER, decodedJWT.getIssuer());
        Assertions.assertEquals(AUDIENCE, decodedJWT.getAudience().get(0));
        Assertions.assertEquals("passfort@163.com", decodedJWT.getClaim("email").asString());
        Assertions.assertEquals("refresh", decodedJWT.getClaim("tokenType").asString());
        Assertions.assertEquals("refreshToken:1:71b16bf8-b014-4808-9ecd-9f698f6f0a44", decodedJWT.getClaim("key").asString());
    }
}