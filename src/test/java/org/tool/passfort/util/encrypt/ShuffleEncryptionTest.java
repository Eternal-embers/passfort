package org.tool.passfort.util.encrypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ShuffleEncryptionTest {
    @Test
    public void testShuffleEncrypt() {
        // 测试数据
        byte[] originalData = "Hello, World! This is a test message.".getBytes();
        int chunkSize = 5; // 每个分片的大小
        int[] shuffleOrder = {2, 0, 3, 1}; // 混淆顺序

        // 调用加密方法
        byte[] encryptedData = ShuffleEncryption.shuffleEncrypt(originalData, chunkSize, shuffleOrder);
        System.out.println("Encrypted data: " + new String(encryptedData));

        // 调用解密方法
        byte[] decryptedData = ShuffleEncryption.shuffleDecrypt(encryptedData, chunkSize, shuffleOrder);
        System.out.println("Decrypted data: " + new String(decryptedData));

        // 验证解密后的数据是否与原始数据一致
        assertArrayEquals(originalData, decryptedData, "encryptedData should match the originalData");
    }
}
