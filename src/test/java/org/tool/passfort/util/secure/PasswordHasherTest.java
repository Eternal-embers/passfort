package org.tool.passfort.util.secure;


import org.junit.jupiter.api.Test;
import org.tool.passfort.util.secure.impl.*;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class PasswordHasherTest {
    @Test
    public void testPasswordHasher() {
        List<PasswordHasher> passwordHashers = new ArrayList<>();

        passwordHashers.add(new BcryptPasswordHasher());
        passwordHashers.add(new PBKDF2PasswordHasher());
        passwordHashers.add(new ScryptPasswordHasher());
        passwordHashers.add(new Argon2PasswordHasher());
        passwordHashers.add(new SHA3PasswordHasher());

        String password = "abcdefghijklmnopqrstuvwxyz1234567890";
        for(PasswordHasher hasher : passwordHashers){
            System.out.println("Testing " + hasher.getClass().getSimpleName());
            try {
                // 测试哈希生成时间
                Instant start = Instant.now();
                byte[] hash = hasher.hashPassword(password);
                Instant end = Instant.now();

                System.out.println("Hashed Password: " + Base64.getEncoder().encodeToString(hash));
                System.out.println("Hash length: " + hash.length + " bytes");
                System.out.println("Hashing time: " + Duration.between(start, end).toMillis() + " ms");

                // 验证密码
                Instant verifyStart = Instant.now();
                boolean isVerified = hasher.verifyPassword(password, hash);
                Instant verifyEnd = Instant.now();
                System.out.println("Password Verified: " + isVerified);
                System.out.println("Verification time: " + Duration.between(verifyStart, verifyEnd).toMillis() + " ms");

                // 添加断言，确保正确密码验证通过
                assert isVerified : "Correct password should be verified successfully.";

                // 验证错误密码
                Instant wrongVerifyStart = Instant.now();
                boolean isVerifiedWrong = hasher.verifyPassword("wrongPassword", hash);
                Instant wrongVerifyEnd = Instant.now();
                System.out.println("Password Verified (Wrong): " + isVerifiedWrong);
                System.out.println("Verification time (Wrong): " + Duration.between(wrongVerifyStart, wrongVerifyEnd).toMillis() + " ms");

                // 添加断言，确保错误密码验证失败
                assert !isVerifiedWrong : "Incorrect password should not be verified successfully.";

                System.out.println();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
