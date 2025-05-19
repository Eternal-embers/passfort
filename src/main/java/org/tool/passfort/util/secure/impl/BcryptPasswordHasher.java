package org.tool.passfort.util.secure.impl;

import org.mindrot.jbcrypt.BCrypt;
import org.tool.passfort.util.secure.PasswordHasher;


/**
 * 使用 bcrypt 算法实现 PasswordHasher 接口。
 */
public class BcryptPasswordHasher implements PasswordHasher {
    // bcrypt 的工作因子（cost factor），值越高，计算越复杂，安全性越高
    private int WORK_FACTOR = 12;

    @Override
    public byte[] hashPassword(String password) throws Exception {
        // 使用 bcrypt 生成哈希值
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(WORK_FACTOR));
        // 将哈希值转换为字节数组返回
        return hashedPassword.getBytes(CHARSET);
    }

    @Override
    public boolean verifyPassword(String inputPassword, byte[] storedHashBytes) throws Exception {
        // 将存储的哈希值字节数组转换为字符串
        String storedHash = new String(storedHashBytes, CHARSET);
        // 使用 bcrypt 验证密码
        return BCrypt.checkpw(inputPassword, storedHash);
    }
}