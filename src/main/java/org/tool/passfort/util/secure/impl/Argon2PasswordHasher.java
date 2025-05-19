package org.tool.passfort.util.secure.impl;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.tool.passfort.util.secure.PasswordHasher;


public class Argon2PasswordHasher implements PasswordHasher {
    private static final int DEFAULT_ITERATIONS = 8; // 迭代次数
    private static final int DEFAULT_MEMORY_COST = 524288; // 内存成本 256MB, 通过占用大量内存来抵抗基于 GPU 或 FPGA 的暴力破解攻击。
    private static final int DEFAULT_PARALLELISM = 8; // 并行度, 设置为服务器 CPU 核心数的 1-2 倍

    /**
     * 对输入的密码进行哈希处理。
     * 该方法应使用生成的盐值（salt）和指定的哈希算法对密码进行哈希处理。
     * 哈希值通常包括盐值和哈希结果，以便在验证时使用。
     *
     * @param password 需要哈希的密码。
     * @return 115字节的哈希值字节数组，包含盐值和哈希结果。
     */
    @Override
    public byte[] hashPassword(String password) {
        try {
            byte[] salt = generateSalt(); // 生成盐值

            /**
             * Argon2Factory.Argon2Types
             * 1. Argon2d
             * 特点：对时间攻击（如 GPU/FPGA 攻击）有很强的抵抗力，但对侧信道攻击（如缓存攻击）的防御能力较弱。
             * 适用场景：适用于对硬件攻击防护要求高，且运行环境相对安全（不易受到侧信道攻击）的场景。
             * 2. Argon2i
             * 特点：对侧信道攻击有较强的防御能力，但对时间攻击的抵抗力相对较弱。
             * 适用场景：适用于对数据安全性要求极高，且可能面临侧信道攻击的场景。
             * 3. Argon2id
             * 特点：结合了 Argon2d 和 Argon2i 的优点，既对时间攻击有较强的抵抗力，又对侧信道攻击有一定的防御能力。
             * 适用场景：是目前推荐的通用变体，适用于大多数场景
             */
            Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

            // 将盐值和哈希结果拼接后返回，存储格式：[盐值（16字节）] + [Argon2的哈希结果字符串]
            String hash = argon2.hash(DEFAULT_ITERATIONS, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, password.toCharArray());

            // 将盐值和哈希结果拼接为一个字节数组
            byte[] hashBytes = hash.getBytes(CHARSET);
            byte[] combined = new byte[salt.length + hashBytes.length];
            System.arraycopy(salt, 0, combined, 0, salt.length); // 将盐值复制到字节数组的前16字节
            System.arraycopy(hashBytes, 0, combined, salt.length, hashBytes.length); // 将哈希结果复制到盐值之后

            return combined;
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    /**
     * 验证输入的密码是否与存储的哈希值匹配。
     * 该方法应从存储的哈希值中提取盐值，使用相同的哈希算法对输入密码进行哈希处理，
     * 然后比较生成的哈希值是否与存储的哈希值一致。
     *
     * @param inputPassword 输入的密码。
     * @param storedHashBytes 存储的哈希值字节数组。
     * @return 如果输入密码与存储的哈希值匹配，返回 true；否则返回 false。
     */
    @Override
    public boolean verifyPassword(String inputPassword, byte[] storedHashBytes) {
        try {
            if (storedHashBytes == null || storedHashBytes.length < SALT_LENGTH) {
                throw new IllegalArgumentException("Invalid stored hash bytes");
            }

            // 从存储的字节数组中提取哈希结果
            byte[] hashBytes = new byte[storedHashBytes.length - SALT_LENGTH];
            System.arraycopy(storedHashBytes, SALT_LENGTH, hashBytes, 0, hashBytes.length);

            String storedHash = new String(hashBytes, CHARSET);

            // 使用相同的盐值重新哈希输入密码
            Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
            return argon2.verify(storedHash, inputPassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to verify password", e);
        }
    }
}