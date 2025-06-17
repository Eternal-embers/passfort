package org.tool.passfort.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.tool.passfort.exception.DatabaseOperationException;
import org.tool.passfort.exception.UnauthorizedException;
import org.tool.passfort.mapper.CredentialEncryptionMapper;
import org.tool.passfort.mapper.CredentialMapper;
import org.tool.passfort.model.Credential;
import org.tool.passfort.model.CredentialEncryption;
import org.tool.passfort.service.CredentialService;
import org.tool.passfort.util.encrypt.AesUtil;

import javax.crypto.SecretKey;
import java.util.List;

@Service
@Transactional(rollbackFor = DatabaseOperationException.class)
public class CredentialServiceImpl implements CredentialService {
    private static final Logger logger = LoggerFactory.getLogger(CredentialServiceImpl.class);
    private final CredentialMapper credentialMapper;
    private final CredentialEncryptionMapper credentialEncryptionMapper;
    private final AesUtil aesUtil;

    @Autowired
    public CredentialServiceImpl(CredentialMapper credentialMapper, CredentialEncryptionMapper credentialEncryptionMapper, AesUtil aesUtil) {
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

        // 构造 CredentialEncryption 对象，mybatis会将生成的主键值赋值给对象的属性encryptionId
        CredentialEncryption credentialEncryption = new CredentialEncryption(iv, key.getEncoded(), encryptedPassword);
        credentialEncryptionMapper.createCredentialEncryption(credentialEncryption); // 将加密凭证存储到凭证加密表

        // 构造 Credential 对象，mybatis会将生成的主键值赋值给对象的属性credentialId
        Credential credential = new Credential(userId, credentialEncryption.getEncryptionId(), platform, account);
        credentialMapper.createCredential(credential);

        return credentialMapper.queryCredentialById(credential.getCredentialId());
    }

    @Override
    public List<Credential> queryCredential(int userId, String platform, String account, boolean valid) {
        return credentialMapper.queryCredential(userId, platform, account, valid);
    }

    @Override
    public String getPassword(int userId, int encryptionId) throws Exception {
        // 验证此密码信息是否属于此用户
        int ownerId;
        try{
            ownerId = credentialMapper.queryUserIdByEncryptionId(encryptionId);
        } catch (NullPointerException e) {
            logger.error("Unauthorized access attempt: User-{} tried to access encryption-{}.", userId, encryptionId);
            throw new UnauthorizedException("Unauthorized access attempt to encryption which belongs to another user.");// 非法操作，用户尝试访问其他用户的密码信息
        }

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

    public void updateAccount(int credentialId, String newAccount){
        int rowCount = credentialMapper.updateCredential(credentialId, null, newAccount, null);
        if (rowCount != 1) {
            logger.error("Failed to update credential account: credentialId={}, newAccount={}", credentialId, newAccount);
        }
    }

    public int updatePassword(int userId, int credentialId, String newPassword) throws Exception {
        // 验证此密码信息是否属于此用户
        int ownerId;
        try {
            ownerId = credentialMapper.queryUserIdByCredentialId(credentialId);
        } catch (NullPointerException e) {
            logger.error("Unauthorized access attempt: User-{} tried to access credential-{}.", userId, credentialId);
            throw new UnauthorizedException("Unauthorized access attempt to credential which belongs to another user.");// 非法操作，用户尝试更新其他用户的密码信息
        }

        if (ownerId != userId) {
            logger.error("Unauthorized access attempt: User-{} tried to access credential-{} which belongs to user-{}.", userId, credentialId, ownerId);
            throw new UnauthorizedException("Unauthorized access attempt to credential which belongs to another user.");// 非法操作，用户尝试更新其他用户的密码信息
        }

        // 创建新的加密信息
        byte[] iv = aesUtil.generateIv();
        SecretKey secretKey = aesUtil.generateAesKey();
        byte[] encryptedPassword = aesUtil.encrypt(newPassword, iv, secretKey);

        // 将新的加密信息存储到凭证加密表
        CredentialEncryption credentialEncryption = new CredentialEncryption(iv, secretKey.getEncoded(), encryptedPassword);
        credentialEncryptionMapper.createCredentialEncryption(credentialEncryption);

        // 更新凭证表中的加密信息 ID
        Integer encryptionId = credentialEncryption.getEncryptionId();
        int rowCount = credentialMapper.updateCredentialEncryption(credentialId, encryptionId);
        if (rowCount != 1) {
            logger.error("Failed to update credential encryption: credentialId={}, encryptionId={}", credentialId, encryptionId);
        }

        return encryptionId;
    }

    @Override
    public void updateValid(int credentialId, boolean valid) {
        int rowCount = credentialMapper.updateCredential(credentialId, null, null, valid);
        if (rowCount != 1) {
            logger.error("Failed to update credential valid: credentialId={}, valid={}", credentialId, valid);
        }
    }
}
