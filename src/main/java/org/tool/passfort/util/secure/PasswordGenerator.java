package org.tool.passfort.util.secure;

import java.security.SecureRandom;

public class PasswordGenerator {
    // 定义密码字符集
    private static final String CHAR_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHAR_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String CHAR_DIGITS = "0123456789";
    private static final String CHAR_SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    // 合并所有字符集
    private static final String CHAR_ALL = CHAR_LOWERCASE + CHAR_UPPERCASE + CHAR_DIGITS + CHAR_SPECIAL;

    // 使用安全的随机数生成器
    private static final SecureRandom random = new SecureRandom();

    /**
     * 生成密码安全
     * @param length 密码长度，建议至少12位
     * @return 生成的安全密码
     */
    public static String generateSecurePassword(int length) {
        if (length < 12) {
            throw new IllegalArgumentException("密码长度至少应为12位");
        }

        StringBuilder password = new StringBuilder(length);

        // 确保密码中至少包含一个大写字母、一个小写字母、一个数字和一个特殊字符
        password.append(CHAR_LOWERCASE.charAt(random.nextInt(CHAR_LOWERCASE.length())));
        password.append(CHAR_UPPERCASE.charAt(random.nextInt(CHAR_UPPERCASE.length())));
        password.append(CHAR_DIGITS.charAt(random.nextInt(CHAR_DIGITS.length())));
        password.append(CHAR_SPECIAL.charAt(random.nextInt(CHAR_SPECIAL.length())));

        // 填充剩余的字符
        for (int i = 4; i < length; i++) {
            password.append(CHAR_ALL.charAt(random.nextInt(CHAR_ALL.length())));
        }

        // 将密码字符打乱顺序，避免前几个字符总是固定的
        char[] passwordArray = password.toString().toCharArray();
        for (int i = 0; i < passwordArray.length; i++) {
            int randomIndex = random.nextInt(passwordArray.length);
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[randomIndex];
            passwordArray[randomIndex] = temp;
        }

        return new String(passwordArray);
    }

    public static void main(String[] args) {
        // 示例：生成一个16位的安全密码
        String password = generateSecurePassword(32);
        System.out.println("生成的安全密码: " + password);
    }
}
