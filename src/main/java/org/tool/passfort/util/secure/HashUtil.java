package org.tool.passfort.util.secure;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;

public class HashUtil {

    public enum HashAlgorithm {
        // MD5：速度快，输出长度为128位（32个十六进制字符）。适合文件完整性校验，但安全性较低，不推荐用于密码存储。
        MD5("MD5"),
        // SHA-1：输出长度为160位（40个十六进制字符）。比MD5更安全，但存在潜在的碰撞风险，不推荐用于高安全性的场景。
        SHA_1("SHA-1"),
        // SHA-256：输出长度为256位（64个十六进制字符）。安全性高，抗碰撞能力强，适合密码存储和文件完整性校验。
        SHA_256("SHA-256"),
        // SHA-512：输出长度为512位（128个十六进制字符）。安全性更高，输出长度更长，适合高安全性的场景。
        SHA_512("SHA-512"),
        // SHA3-256：输出长度为256位（64个十六进制字符）。SHA-3系列，设计上更加安全，抗碰撞能力更强。
        SHA3_256("SHA3-256"),
        // SHA3-512：输出长度为512位（128个十六进制字符）。SHA-3系列，输出长度更长，安全性更高。
        SHA3_512("SHA3-512");

        private final String algorithmName;

        HashAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        public String getAlgorithmName() {
            return algorithmName;
        }
    }

    /**
     * 对文本进行哈希处理
     *
     * @param text        需要哈希的文本
     * @param algorithm   哈希算法类型
     * @return            哈希值（16进制字符串）
     */
    public static String hashText(String text, HashAlgorithm algorithm) {
        try {
            // 获取指定算法的MessageDigest实例
            MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithmName());

            // 对文本进行哈希处理
            byte[] encodedHash = digest.digest(text.getBytes());

            // 将哈希值转换为16进制字符串
            StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
            for (byte hash : encodedHash) {
                String hex = Integer.toHexString(0xff & hash);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希算法不支持: " + algorithm, e);
        }
    }

    /**
     *  验证文本是否与给定的哈希值匹配
     */
    public static boolean verifyTextHash(String text, String hash, HashAlgorithm algorithm) {
        return hashText(text, algorithm).equals(hash);
    }

    /**
     * 比对两个文本的哈希值是否一致
     *
     * @param text1       第一个文本
     * @param text2       第二个文本
     * @param algorithm   哈希算法类型
     * @return            如果哈希值一致返回true，否则返回false
     */
    public static boolean compareTextHashes(String text1, String text2, HashAlgorithm algorithm) {
        String hash1 = hashText(text1, algorithm);
        String hash2 = hashText(text2, algorithm);
        return hash1.equals(hash2);
    }

    // 哈希算法对比
    public static void main(String[] args) {
        // 测试文本
        // 生成一个长度为 1024 的随机字符串
        String text = ThreadLocalRandom.current().ints(32, 97, 123)
                .mapToObj(c -> String.valueOf((char) c))
                .reduce("", String::concat);

        // 遍历所有哈希算法
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            long startTime = System.nanoTime(); // 使用纳秒级时间测量

            // 计算哈希值
            String hashValue = hashText(text, algorithm);

            long endTime = System.nanoTime(); // 结束时间
            long duration = (endTime - startTime) / 1_000_000; // 转换为毫秒

            // 计算哈希值的字节大小
            int hashSize = hashValue.length() / 2; // 每个十六进制字符代表4个比特，即半个字节

            // 计算哈希字符串的长度（以字符数为单位）
            int hashStringLength = hashValue.length(); // 十六进制字符串的长度

            // 打印结果
            System.out.println("Algorithm: " + algorithm.getAlgorithmName());
            System.out.println("Hash Value: " + hashValue);
            System.out.println("Hash Size: " + hashSize + " bytes");
            System.out.println("Hash String Length(Hex): " + hashStringLength + " characters");
            System.out.println("Duration: " + duration + " ms");
            System.out.println("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
        }
    }
}
