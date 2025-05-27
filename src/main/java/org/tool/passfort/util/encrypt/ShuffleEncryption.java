package org.tool.passfort.util.encrypt;
import java.util.Arrays;

public class ShuffleEncryption {

    // 分片混淆加密方法
    public static byte[] shuffleEncrypt(byte[] data, int chunkSize, int[] shuffleOrder) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("Chunk size must be greater than 0");
        }
        if (shuffleOrder == null || shuffleOrder.length == 0) {
            throw new IllegalArgumentException("Shuffle order must not be empty");
        }

        // 计算总片段数
        int totalChunks = (data.length + chunkSize - 1) / chunkSize;

        // 检查 shuffleOrder 是否合法
        if (shuffleOrder.length != totalChunks) {
            throw new IllegalArgumentException("Shuffle order length does not match the number of chunks");
        }

        // 创建一个数组来存储打乱后的数据
        byte[] shuffledData = new byte[data.length];

        // 按照 shuffleOrder 打乱数据
        for (int i = 0; i < totalChunks; i++) {
            int srcIndex = i * chunkSize;
            int destIndex = shuffleOrder[i] * chunkSize;
            int length = Math.min(chunkSize, data.length - srcIndex);
            System.arraycopy(data, srcIndex, shuffledData, destIndex, length);
        }

        return shuffledData;
    }

    // 解密方法
    public static byte[] shuffleDecrypt(byte[] shuffledData, int chunkSize, int[] shuffleOrder) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("Chunk size must be greater than 0");
        }
        if (shuffleOrder == null || shuffleOrder.length == 0) {
            throw new IllegalArgumentException("Shuffle order must not be empty");
        }

        // 计算总片段数
        int totalChunks = (shuffledData.length + chunkSize - 1) / chunkSize;

        // 检查 shuffleOrder 是否合法
        if (shuffleOrder.length != totalChunks) {
            throw new IllegalArgumentException("Shuffle order length does not match the number of chunks");
        }

        // 创建一个数组来存储恢复后的数据
        byte[] originalData = new byte[shuffledData.length];

        // 按照 shuffleOrder 恢复数据
        for (int i = 0; i < totalChunks; i++) {
            int srcIndex = shuffleOrder[i] * chunkSize;
            int destIndex = i * chunkSize;
            int length = Math.min(chunkSize, shuffledData.length - srcIndex);
            System.arraycopy(shuffledData, srcIndex, originalData, destIndex, length);
        }

        return originalData;
    }

    public static void main(String[] args) {
        // 示例数据
        byte[] data = "HelloWorld1234567890".getBytes();
        int chunkSize = 4; // 每个片段大小
        int[] shuffleOrder = {2, 0, 4, 3, 1}; // 打乱顺序

        // 加密
        byte[] encryptedData = shuffleEncrypt(data, chunkSize, shuffleOrder);
        System.out.println("Encrypted Data: " + Arrays.toString(encryptedData));

        // 解密
        byte[] decryptedData = shuffleDecrypt(encryptedData, chunkSize, shuffleOrder);
        System.out.println("Decrypted Data: " + new String(decryptedData));
    }
}