package org.tool.passfort.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tool.passfort.exception.UnauthorizedException;
import org.tool.passfort.mapper.CredentialChangeLogMapper;
import org.tool.passfort.mapper.CredentialEncryptionMapper;
import org.tool.passfort.mapper.CredentialMapper;
import org.tool.passfort.model.Credential;
import org.tool.passfort.model.CredentialEncryption;
import org.tool.passfort.service.CredentialService;
import org.tool.passfort.util.encrypt.AesUtil;

import javax.crypto.SecretKey;
import java.util.List;

@Service
public class CredentialServiceImpl implements CredentialService {
    private static final Logger logger = LoggerFactory.getLogger(CredentialServiceImpl.class);
    private final CredentialMapper credentialMapper;
    private final CredentialEncryptionMapper credentialEncryptionMapper;
    private final AesUtil aesUtil;

    @Autowired
    public CredentialServiceImpl(CredentialMapper credentialMapper, CredentialEncryptionMapper credentialEncryptionMapper, CredentialChangeLogMapper credentialChangeLogMapper, AesUtil aesUtil) {
        this.credentialMapper = credentialMapper;
        this.credentialEncryptionMapper = credentialEncryptionMapper;
        this.aesUtil = aesUtil;
    }

    @Override
    public Credential createCredential(int userId, String platform, String account, String password) throws Exception {
        // 对密码进行对称加密
        SecretKey key = aesUtil.generateAesKey();
        byte[] iv = aesUtil.generateIv();
        byte[] encryptedPassword = aesUtil.encrypt(password, iv, key);

        // 将加密凭证存储到凭证加密表
        Integer encryptionId = credentialEncryptionMapper.createCredentialEncryption(iv, key.getEncoded(), encryptedPassword);
        Integer credentialId = credentialMapper.createCredential(userId, encryptionId, platform, account);

        return credentialMapper.queryCredentialById(credentialId);
    }

    @Override
    public List<Credential> queryCredential(Integer userId, String platform, String account, Boolean valid) {
        return credentialMapper.queryCredential(userId, platform, account, valid);
    }

    @Override
    public String getPassword(Integer userId, Integer encryptionId) throws Exception {
        // 验证此密码信息是否属于此用户
        int ownerId = credentialMapper.queryUserIdByEncryptionId(encryptionId);
        if (ownerId != userId) {
            logger.error("Unauthorized access attempt: User-{} tried to access encryption-{} which belongs to user-{}.", userId, encryptionId, ownerId);
            throw new UnauthorizedException("Unauthorized access attempt to encryption which belongs to another user.");// 非法操作，用户尝试访问其他用户的密码信息
        }

        CredentialEncryption credentialEncryption = credentialEncryptionMapper.selectCredentialEncryptionById(encryptionId);
        byte[] iv = credentialEncryption.getIv();
        SecretKey key = aesUtil.recoverSecretKey(credentialEncryption.getSecretKey());
        byte[] encryptedPassword = credentialEncryption.getEncryptedPassword();

        return aesUtil.decrypt(encryptedPassword, iv, key);
    }
}
