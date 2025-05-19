package org.tool.passfort.util.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWTVerifier;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

public class JwtUtil {
    private String issuer;  // JWT 的签发者, 通常是生成JWT的服务或系统的名称或者组织或公司的名称
    private String audience; // JWT 的接收者, 用于指定这个Token是为谁生成的，例如 https://example.com/
    private Algorithm algorithm; // 签名算法

    public JwtUtil (String issuer, String audience, Algorithm algorithm) {
        this.issuer = issuer;
        this.audience = audience;
        this.algorithm = algorithm;
    }

    /**
     * 创建JWT Token
     * @param subject 主题, 它通常用于表示JWT所代表的实体，例如用户、资源或其他对象
     * @param claims    自定义声明（如用户名、用户ID等）
     * @param expireTime 过期时间（秒）
     * @return JWT Token
     */
    public String createToken(String subject, Map<String, String> claims, long expireTime) {
        Date issuedAt = new Date();// 获取当前时间作为Token的签发时间
        Date expiresAt = new Date(issuedAt.getTime() + expireTime * 1000);//// 计算Token的过期时间
        Date notBefore = new Date(); // 设置JWT的生效时间（立即生效）

        // 创建JWT构建器
        JWTCreator.Builder builder = JWT.create()
                .withSubject(subject) // 设置JWT的主题
                .withIssuer(issuer) // 设置JWT的签发者
                .withAudience(audience) // 设置JWT的接收者
                .withIssuedAt(issuedAt) // 设置Token的签发时间
                .withExpiresAt(expiresAt) // 设置Token的过期时间
                .withNotBefore(notBefore) // 设置Token的生效时间
                .withJWTId(UUID.randomUUID().toString()); // 设置JWT的唯一标识符

        // 添加自定义声明
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            builder.withClaim(entry.getKey(), entry.getValue());
        }

        return builder.sign(algorithm);// 使用算法和密钥对JWT进行签名，并返回生成的Token字符串
    }

    /**
     * 验证 JWT 令牌是否有效。
     * @param subject 令牌的主题（subject）。
     * @param token 要验证的 JWT 令牌字符串。
     * @return 返回解码后的 JWT 对象（DecodedJWT），其中包含令牌中的声明（claims）。
     * @throws JWTVerificationException 如果令牌验证失败，会抛出此异常。可能的原因包括：
     *                                  - 令牌格式错误
     *                                  - 签名验证失败
     *                                  - 令牌已过期
     *                                  - 令牌尚未生效（nbf 声明）
     *                                  - 主题（subject）、签发者（issuer）或接收者（audience）不匹配
     */
    public DecodedJWT verifyToken(String subject, String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(algorithm)
                .withSubject(subject)
                .withIssuer(issuer)
                .withAudience(audience)
                .build();

        return verifier.verify(token);
    }
}