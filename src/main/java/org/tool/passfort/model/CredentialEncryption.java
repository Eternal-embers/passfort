package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialEncryption {
    private Integer encryptionId; // 加密信息的唯一标识，自增主键
    private byte[] iv; // 初始化向量（IV），用于加密算法，长度为16字节
    private byte[] secretKey; // 密钥，用于加密算法，长度为32字节
    private byte[] encryptedPassword; // 加密后的密码，最大长度为512字节

    public CredentialEncryption(byte[] iv, byte[] secretKey, byte[] encryptedPassword) {
        this.iv = iv;
        this.secretKey = secretKey;
        this.encryptedPassword = encryptedPassword;
    }
}
