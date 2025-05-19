package org.tool.passfort.util.jwt;

import java.security.SecureRandom;
import java.util.Base64;

public class JwtSecretKeyGenerator {

    public static String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64]; // 64 字节，即 512 位
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static void main(String[] args) {
        String secretKey = generateSecretKey();
        System.out.println("生成的 JWT Secret Key: " + secretKey);
    }
}