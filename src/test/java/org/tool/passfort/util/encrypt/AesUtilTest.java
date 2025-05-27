package org.tool.passfort.util.encrypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Random;

public class AesUtilTest {
    private AesUtil aesUtil;

    public AesUtilTest() {
        this.aesUtil = new AesUtil();
    }

    @Test
    public void testGenerateAesKey() throws Exception {
        // 测试生成AES密钥
        SecretKey key = aesUtil.generateAesKey();
        Assertions.assertNotNull(key, "生成的AES密钥不能为空");
        Assertions.assertEquals(256, key.getEncoded().length * 8, "AES密钥长度应为256位");
    }

    @Test
    public void testRecoverSecretKey() throws Exception {
        // 测试恢复密钥
        SecretKey originalKey = aesUtil.generateAesKey();
        byte[] keyBytes = originalKey.getEncoded();
        SecretKey recoveredKey = aesUtil.recoverSecretKey(keyBytes);
        Assertions.assertArrayEquals(originalKey.getEncoded(), recoveredKey.getEncoded(), "恢复的密钥应与原始密钥一致");
    }

    @Test
    public void testGenerateIv() throws Exception {
        // 测试生成IV
        byte[] iv = aesUtil.generateIv();
        Assertions.assertNotNull(iv, "生成的IV不能为空");
        Assertions.assertEquals(16, iv.length, "IV长度应为16字节");
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        // 测试加密和解密
        String originalData = "Hello, AES!";
        SecretKey key = aesUtil.generateAesKey();
        byte[] iv = aesUtil.generateIv();

        byte[] encryptedData = aesUtil.encrypt(originalData, iv, key);
        String decryptedData = aesUtil.decrypt(encryptedData, iv, key);

        Assertions.assertNotEquals(originalData, Base64.getEncoder().encodeToString(encryptedData), "加密后的数据应与原始数据不同");
        Assertions.assertEquals(originalData, decryptedData, "解密后的数据应与原始数据一致");
    }

    @Test
    public void testEncryptionDecryptionPerformance() throws Exception {
        // 测试性能
        String largeData = generateLargeData(1024 * 1024); // 生成1MB的测试数据
        SecretKey key = aesUtil.generateAesKey();
        byte[] iv = aesUtil.generateIv();

        long startTime = System.currentTimeMillis();
        byte[] encryptedData = aesUtil.encrypt(largeData, iv, key);
        long encryptionTime = System.currentTimeMillis() - startTime;

        startTime = System.currentTimeMillis();
        String decryptedData = aesUtil.decrypt(encryptedData, iv, key);
        long decryptionTime = System.currentTimeMillis() - startTime;

        Assertions.assertEquals(largeData, decryptedData, "解密后的数据应与原始数据一致");

        System.out.println("加密耗时: " + encryptionTime + " ms");
        System.out.println("解密耗时: " + decryptionTime + " ms");
    }

    private String generateLargeData(int size) {
        // 生成指定大小的随机字符串
        Random random = new Random();
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }
}
