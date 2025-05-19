package org.tool.passfort.util.secure.impl;

import com.lambdaworks.crypto.SCrypt;
import org.tool.passfort.util.secure.PasswordHasher;
import java.security.MessageDigest;

public class ScryptPasswordHasher implements PasswordHasher {
    private static final int N = 65536; // 内存成本因子，值越高，内存和CPU占用越大，安全性越高, 2^18
    private static final int R = 8;    // 块大小，影响内存和CPU的使用
    private static final int P = 2;    // 并行度，通常为1
    private static final int KEY_LENGTH = 64; // 输出密钥长度，单位为字节

    @Override
    public byte[] hashPassword(String password) throws Exception {
        byte[] salt = generateSalt(); // 生成盐值
        byte[] passwordBytes = password.getBytes(CHARSET); // 将密码转换为字节数组
        byte[] derivedKey = SCrypt.scrypt(passwordBytes, salt, N, R, P, KEY_LENGTH); // 使用Scrypt算法生成哈希值
        byte[] combined = new byte[SALT_LENGTH + KEY_LENGTH]; // 创建一个数组，用于存储盐值和哈希值
        System.arraycopy(salt, 0, combined, 0, SALT_LENGTH); // 将盐值复制到数组的前半部分
        System.arraycopy(derivedKey, 0, combined, SALT_LENGTH, KEY_LENGTH); // 将哈希值复制到数组的后半部分
        return combined; // 返回包含盐值和哈希值的字节数组
    }

    @Override
    public boolean verifyPassword(String inputPassword, byte[] storedHashBytes) throws Exception {
        byte[] salt = new byte[SALT_LENGTH]; // 提取盐值
        byte[] storedDerivedKey = new byte[KEY_LENGTH]; // 提取存储的哈希值
        System.arraycopy(storedHashBytes, 0, salt, 0, SALT_LENGTH); // 将盐值从存储的哈希值中提取出来
        System.arraycopy(storedHashBytes, SALT_LENGTH, storedDerivedKey, 0, KEY_LENGTH); // 将哈希值从存储的哈希值中提取出来

        byte[] inputPasswordBytes = inputPassword.getBytes(CHARSET); // 将输入的密码转换为字节数组
        byte[] inputDerivedKey = SCrypt.scrypt(inputPasswordBytes, salt, N, R, P, KEY_LENGTH); // 使用相同的盐值和参数生成输入密码的哈希值

        // 比较哈希值, 避免时间攻击（timing attack）
        return MessageDigest.isEqual(inputDerivedKey, storedDerivedKey);
    }
}
