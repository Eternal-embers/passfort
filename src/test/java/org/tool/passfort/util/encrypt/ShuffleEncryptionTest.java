package org.tool.passfort.util.encrypt;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ShuffleEncryptionTest {
    @Test
    public void testShuffleEncrypt() {
        // 测试数据
        String refreshToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiUGFzc0ZvcnQiLCJhdWQiOiJodHRwczovL2xvY2FsaG9zdC9wYXNzZm9ydC8iLCJpYXQiOjE3NTAwNTcxNzksImV4cCI6MTc1MDA2MDc3OSwibmJmIjoxNzUwMDU3MTc5LCJqdGkiOiI3YTY2Yzc0YS0wMTM2LTQ5YWUtOTM4Yi1kYTZlNDI0YzhkNWUiLCJ0b2tlblR5cGUiOiJyZWZyZXNoIiwiZW1haWwiOiJwYXNzZm9ydEAxNjMuY29tIiwia2V5IjoicmVmcmVzaFRva2VuOjE6NzFiMTZiZjgtYjAxNC00ODA4LTllY2QtOWY2OThmNmYwYTQ0In0.boG1UUZPGD8Exa_TSDBSIOhoqjafqZP-Y8M4Ydwcah5fIFRf9JDt5L1bu_PeOlKIqZZHrJ4BW7yNSbw9aQf4tQ";
        byte[] originalData = refreshToken.getBytes();
        int[] shuffleOrder = ShuffleEncryption.generateShuffleOrder(16); // 混淆顺序


        System.out.println("refreshToken: " + refreshToken);
        System.out.println("refreshToken byte size: " + originalData.length);
        System.out.println("Shuffle order: " + Arrays.toString(shuffleOrder));
        System.out.println("Shuffle order length: " + shuffleOrder.length);

        // 调用加密方法
        byte[] encryptedData = ShuffleEncryption.shuffleEncrypt(originalData, shuffleOrder);
        System.out.println("Encrypted data: " + new String(encryptedData));

        // 调用解密方法
        byte[] decryptedData = ShuffleEncryption.shuffleDecrypt(encryptedData, shuffleOrder);
        System.out.println("Decrypted data: " + new String(decryptedData));

        // 验证解密后的数据是否与原始数据一致
        assertArrayEquals(originalData, decryptedData, "encryptedData should match the originalData");
    }
}
