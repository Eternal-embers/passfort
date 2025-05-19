package org.tool.passfort.util.encrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AesUtil {
    private static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256; // 密钥长度
    private static final int IV_SIZE = 128; // IV长度
    private static final String algorithm = "AES";

    /**
     * 生成AES密钥
     * @return AES密钥
     * @throws Exception
     */
    public static SecretKey generateAesKey() throws Exception {
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
    public static SecretKey recoverSecretKey(byte[] keyBytes) {
        // 使用SecretKeySpec从字节序列和算法名称创建一个新的SecretKey对象
        SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);
        return secretKey;
    }

    /**
     * 生成AES算法的初始化向量IV
     * @return IV的字节数组
     * @throws Exception
     */
    public static byte[] generateIv() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE / 8];
        random.nextBytes(iv);

        return iv;
    }

    /**
     * AES加密数据
     * @param data 待加密数据字符串
     * @param key AES密钥
     * @param iv AES算法的初始化向量IV
     * @return 加密后的数据字节数组
     * @throws Exception
     */
    public static byte[] encrypt(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return encrypted;
    }

    /**
     * 解密AES加密数据
     * @param encryptedData 加密后的数据字节数组
     * @param key AES密钥
     * @param iv AES算法的初始化向量IV
     * @return 解密后的数据字符串
     * @throws Exception
     */
    public static String decrypt(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] original = cipher.doFinal(encryptedData);
        return new String(original);
    }
}
