package org.tool.passfort.util.secure.impl;

import org.tool.passfort.util.secure.PasswordHasher;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.spec.KeySpec;

/**
 * PBKDF2 实现类，继承自 PasswordHasher 接口。
 */
public class PBKDF2PasswordHasher implements PasswordHasher {
    private static final int ITERATIONS = 1048576; // 迭代次数,2^20
    private static final int KEY_LENGTH = 512; // 哈希结果长度（512位）
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512"; // 哈希算法

    /**
     * 对输入的密码进行哈希处理。
     * @param password 需要哈希的密码。
     * @return 哈希后的字节数组，通常包含盐值和哈希结果, 96字节
     * @throws Exception
     */
    @Override
    public byte[] hashPassword(String password) throws Exception {
        byte[] salt = generateSalt();// 生成盐值
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);// 创建 PBEKeySpec
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);// 获取 SecretKeyFactory
        byte[] hash = factory.generateSecret(spec).getEncoded();// 生成哈希值 64字节

        // 将盐值和哈希值拼接起来，便于存储和验证
        byte[] combined = new byte[salt.length + hash.length];// 96字节
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);

        return combined;
    }

    @Override
    public boolean verifyPassword(String inputPassword, byte[] storedHashBytes) throws Exception {
        // 从存储的哈希值中提取盐值
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(storedHashBytes, 0, salt, 0, SALT_LENGTH);

        // 提取哈希值
        byte[] storedHash = new byte[storedHashBytes.length - SALT_LENGTH];
        System.arraycopy(storedHashBytes, SALT_LENGTH, storedHash, 0, storedHash.length);

        // 使用相同的盐值和参数对输入密码进行哈希
        KeySpec spec = new PBEKeySpec(inputPassword.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] hash = factory.generateSecret(spec).getEncoded();

        // 比较哈希值, 避免时间攻击（timing attack）
        return MessageDigest.isEqual(hash, storedHash);
    }
}