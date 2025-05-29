package org.tool.passfort.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tool.passfort.mapper.CredentialEncryptionMapper;
import org.tool.passfort.mapper.CredentialHistoryMapper;
import org.tool.passfort.model.CredentialEncryption;
import org.tool.passfort.model.CredentialHistory;
import org.tool.passfort.service.CredentialHistoryService;
import org.tool.passfort.util.encrypt.AesUtil;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class CredentialHistoryServiceImpl implements CredentialHistoryService {
    private final CredentialHistoryMapper credentialHistoryMapper;
    private final CredentialEncryptionMapper credentialEncryptionMapper;
    private final AesUtil aesUtil;

    @Autowired
    public CredentialHistoryServiceImpl(CredentialHistoryMapper credentialHistoryMapper, CredentialEncryptionMapper credentialEncryptionMapper, AesUtil aesUtil) {
        this.credentialHistoryMapper = credentialHistoryMapper;
        this.credentialEncryptionMapper = credentialEncryptionMapper;
        this.aesUtil = aesUtil;
    }


    @Override
    public List<CredentialHistory> getAccountHistory(int userId, int credentialId) {
        return credentialHistoryMapper.getAccountHistory(userId, credentialId);
    }

    @Override
    public String getPassword(int userId, int historyId) throws Exception {
        // 获取凭证历史对应的加密信息
        int encryptionId = credentialHistoryMapper.selectEncryptionIdByHistoryId(historyId);
        CredentialEncryption credentialEncryption = credentialEncryptionMapper.selectCredentialEncryptionById(encryptionId);

        // 解密
        byte[] encryptedPassword = credentialEncryption.getEncryptedPassword();
        byte[] iv = credentialEncryption.getIv();
        byte[] secretKey = credentialEncryption.getSecretKey();
        String decryptedPassword = aesUtil.decrypt(encryptedPassword, iv, aesUtil.recoverSecretKey(secretKey));

        return decryptedPassword;
    }

    @Override
    public void deleteAccountHistory(int userId, int historyId) {
        credentialHistoryMapper.deleteByHistoryId(historyId);
    }

    @Override
    public void deleteAccountHistory(int userId, int credentialId, LocalDateTime createdAt) {
        credentialHistoryMapper.deleteByCreatedAtBefore(userId, credentialId, createdAt);
    }
}
