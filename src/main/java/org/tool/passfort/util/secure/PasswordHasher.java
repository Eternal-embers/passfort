package org.tool.passfort.util.secure;

import java.security.SecureRandom;

/**
 * PasswordHasher 接口定义了密码哈希和验证的基本功能。
 * 它提供了一个默认的生成盐值（salt）的方法，以及密码哈希和验证的方法。
 * 实现该接口的类需要提供具体的哈希算法实现。
 */
public interface PasswordHasher {
    int SALT_LENGTH = 32; // 盐值长度（32字节）
    String CHARSET = "UTF-8"; // 字符集

    /**
     * 生成一个随机的盐值（salt），用于增强密码哈希的安全性。
     * 盐值是随机生成的，以确保每个用户的盐值都是唯一的。
     * 使用盐值可以有效防止彩虹表攻击和暴力破解。
     *
     * @return 一个 32 字节的随机盐值。
     */
    default byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH]; // 16 字节的盐值
        random.nextBytes(salt);
        return salt;
    }

    /**
     * 对输入的密码进行哈希处理。
     * 该方法应使用生成的盐值（salt）和指定的哈希算法对密码进行哈希处理。
     * 哈希值通常包括盐值和哈希结果，以便在验证时使用。
     *
     * @param password 需要哈希的密码。
     * @return 哈希后的字节数组，通常包含盐值和哈希结果。
     * @throws Exception 如果哈希过程中发生错误。
     */
    byte[] hashPassword(String password) throws Exception;

    /**
     * 验证输入的密码是否与存储的哈希值匹配。
     * 该方法应从存储的哈希值中提取盐值，使用相同的哈希算法对输入密码进行哈希处理，
     * 然后比较生成的哈希值是否与存储的哈希值一致。
     *
     * @param inputPassword 输入的密码。
     * @param storedHashBytes 存储的哈希值字节数组。
     * @return 如果输入密码与存储的哈希值匹配，返回 true；否则返回 false。
     * @throws Exception 如果验证过程中发生错误。
     */
    boolean verifyPassword(String inputPassword, byte[] storedHashBytes) throws Exception;
}