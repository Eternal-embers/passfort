package org.tool.passfort.util.encrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AesUtil {
    private final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    private final int KEY_SIZE = 256; // 密钥长度， 256位=32字节
    private final int IV_SIZE = 128; // IV长度，128位=16字节
    private final String algorithm = "AES";

    /**
     * 生成AES密钥, 调用 getEncoded() 方法获取密钥的字节序列
     * @return AES密钥
     */
    public SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(KEY_SIZE, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }

    /**
     * 从字节序列恢复SecretKey对象。
     *
     * @param keyBytes   密钥的字节序列
     * @return 恢复的SecretKey对象
     */
    public SecretKey recoverSecretKey(byte[] keyBytes) {
        // 使用SecretKeySpec从字节序列和算法名称创建一个新的SecretKey对象
        SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);
        return secretKey;
    }

    /**
     * 生成AES算法的初始化向量IV
     * @return IV的字节数组
     */
    public byte[] generateIv() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE / 8];
        random.nextBytes(iv);

        return iv;
    }

    /**
     * AES加密数据
     * @param data 待加密数据字符串
     * @param iv AES算法的初始化向量IV
     * @param key AES密钥
     * @return 加密后的数据字节数组
     * @throws Exception
     */
    public byte[] encrypt(String data, byte[] iv, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return encrypted;
    }

    /**
     * 加密AES数据
     * @param data 待加密数据字符串
     * @return iv、key、encryptedData 组合的字节数组，64字节
     * @throws Exception
     */
    public byte[] encrypt(String data) throws Exception {
        // 生成AES算法的初始化向量IV和密钥
        byte[] iv = generateIv();
        SecretKey key = generateAesKey();

        // 加密数据
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());

        // 将 IV、密钥和加密数据拼接在一起
        byte[] result = new byte[iv.length + key.getEncoded().length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(key.getEncoded(), 0, result, iv.length, key.getEncoded().length);
        System.arraycopy(encrypted, 0, result, iv.length + key.getEncoded().length, encrypted.length);

        return result;
    }

    /**
     * 解密AES加密数据
     * @param encryptedData 加密后的数据字节数组
     * @param iv AES算法的初始化向量IV
     * @param key AES密钥
     * @return 解密后的数据字符串
     * @throws Exception
     */
    public String decrypt(byte[] encryptedData, byte[] iv, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] original = cipher.doFinal(encryptedData);
        return new String(original);
    }
}
