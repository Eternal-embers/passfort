package org.tool.passfort.util.secure.impl;

import org.tool.passfort.util.secure.PasswordHasher;
import java.security.MessageDigest;

public class SHA3PasswordHasher implements PasswordHasher {
    private static final String HASH_ALGORITHM = "SHA3-256"; // 使用SHA-3 256位哈希算法

    @Override
    public byte[] hashPassword(String password) throws Exception {
        byte[] salt = generateSalt();// 生成盐值，用于增强密码哈希的安全性

        return hashPasswordWithSalt(password, salt);// 使用盐值对密码进行哈希处理
    }

    @Override
    public boolean verifyPassword(String inputPassword, byte[] storedHashBytes) throws Exception {
        // 提取存储的哈希值中的盐值部分
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(storedHashBytes, 0, salt, 0, SALT_LENGTH);

        // 使用相同的盐值对输入密码进行哈希处理
        byte[] inputHash = hashPasswordWithSalt(inputPassword, salt);

        // 使用MessageDigest的isEqual方法安全地比较生成的哈希值与存储的哈希值
        // 该方法可以防止时间攻击（timing attack）
        return MessageDigest.isEqual(inputHash, storedHashBytes);
    }

    private byte[] hashPasswordWithSalt(String password, byte[] salt) throws Exception {
        // 将密码转换为字节数组，使用UTF-8字符集编码
        byte[] passwordBytes = password.getBytes(CHARSET);

        // 创建一个足够大的数组来存储盐值和密码的字节
        byte[] saltedPassword = new byte[salt.length + passwordBytes.length];

        // 将盐值和密码字节依次拷贝到新的数组中
        System.arraycopy(salt, 0, saltedPassword, 0, salt.length);
        System.arraycopy(passwordBytes, 0, saltedPassword, salt.length, passwordBytes.length);

        // 获取SHA-3算法的MessageDigest实例
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hash = digest.digest(saltedPassword);// 对盐值和密码的组合进行哈希处理

        // 创建一个足够大的数组来存储盐值和哈希结果
        byte[] combined = new byte[salt.length + hash.length];

        // 将盐值和哈希结果依次拷贝到新的数组中
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);

        // 返回包含盐值和哈希结果的字节数组
        return combined;
    }
}