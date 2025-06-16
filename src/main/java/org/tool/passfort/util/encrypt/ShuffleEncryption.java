package org.tool.passfort.util.encrypt;
import java.security.SecureRandom;

public class ShuffleEncryption {
    /**
     * 生成打乱顺序
     * @param totalChunks 完整分片的数量
     * @return 打乱顺序
     */
    public static int[] generateShuffleOrder(int totalChunks) {
        int[] shuffleOrder = new int[totalChunks];
        // 初始化为顺序排列
        for (int i = 0; i < totalChunks; i++) {
            shuffleOrder[i] = i;
        }

        // 使用 SecureRandom 打乱顺序
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < totalChunks; i++) {
            // 随机选择一个索引，确保随机索引不等于当前索引
            int randomIndex;
            do {
                randomIndex = random.nextInt(totalChunks);
            } while (randomIndex == i); // 如果随机索引等于当前索引，则重新生成

            // 交换当前索引和随机索引的值
            int temp = shuffleOrder[i];
            shuffleOrder[i] = shuffleOrder[randomIndex];
            shuffleOrder[randomIndex] = temp;
        }

        return shuffleOrder;
    }

    /**
     * 分片混淆加密方法
     * @param data 原始数据
     * @param shuffleOrder 打乱顺序
     * @return 加密后的数据
     */
    public static byte[] shuffleEncrypt(byte[] data, int[] shuffleOrder) {
        if (shuffleOrder == null || shuffleOrder.length == 0) {
            throw new IllegalArgumentException("Shuffle order must not be empty");
        }


        int totalChunks = shuffleOrder.length;     // shuffleOrder 的长度即完整分片的数量
        int chunkSize = data.length / totalChunks; // 计算每个分片的大小（chunkSize）
        int remainder = data.length % totalChunks; // 计算尾部剩余字节的数量
        byte[] shuffledData = new byte[data.length]; // 创建一个数组来存储打乱后的数据

        // 按照 shuffleOrder 打乱数据（只处理完整分片的部分，数据尾部小于 chunkSize 的部分不处理）
        for (int i = 0; i < totalChunks; i++) {
            int srcIndex = i * chunkSize;
            int destIndex = shuffleOrder[i] * chunkSize;
            System.arraycopy(data, srcIndex, shuffledData, destIndex, chunkSize);
        }

        // 处理尾部剩余字节
        if (remainder > 0) {
            int lastChunkIndex = totalChunks * chunkSize; // 尾部数据的起始位置
            System.arraycopy(data, lastChunkIndex, shuffledData, lastChunkIndex, remainder);
        }

        return shuffledData;
    }

    /**
     * 分片混淆解密方法
     * @param shuffledData 加密后的数据
     * @param shuffleOrder 打乱顺序
     * @return 解密后的数据
     */
    public static byte[] shuffleDecrypt(byte[] shuffledData, int[] shuffleOrder) {
        if (shuffleOrder == null || shuffleOrder.length == 0) {
            throw new IllegalArgumentException("Shuffle order must not be empty");
        }

        int totalChunks = shuffleOrder.length;     // shuffleOrder 的长度即完整分片的数量
        int chunkSize = shuffledData.length / totalChunks; // 计算每个分片的大小（chunkSize）
        int remainder = shuffledData.length % totalChunks; // 计算尾部剩余字节的数量
        byte[] originalData = new byte[shuffledData.length]; // 创建一个数组来存储恢复后的数据

        // 按照 shuffleOrder 恢复数据（只处理完整分片的部分，数据尾部小于 chunkSize 的部分不处理）
        for (int i = 0; i < totalChunks; i++) {
            int srcIndex = shuffleOrder[i] * chunkSize;
            int destIndex = i * chunkSize;
            System.arraycopy(shuffledData, srcIndex, originalData, destIndex, chunkSize);
        }

        // 处理尾部剩余字节
        if (remainder > 0) {
            int lastChunkIndex = totalChunks * chunkSize; // 尾部数据的起始位置
            System.arraycopy(shuffledData, lastChunkIndex, originalData, lastChunkIndex, remainder);
        }

        return originalData;
    }
}