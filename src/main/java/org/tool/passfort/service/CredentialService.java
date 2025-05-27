package org.tool.passfort.service;

import org.tool.passfort.model.Credential;

import java.util.List;

public interface CredentialService {
    /**
     * 创建凭证，将密码加密存储到 credential_encryption
     * @param userId 用户 ID
     * @param platform 平台名称
     * @param account 平台上的账号
     * @param password 密码
     * @return 创建成功返回 true, 否则返回 false
     */
    Credential createCredential(int userId, String platform, String account, String password) throws Exception;

    /**
     * 查询凭证
     * @param userId 用户 ID
     * @param platform 平台名称
     * @param account 平台上的账号
     * @param valid 是否有效
     * @return 凭证列表
     */
    List<Credential> queryCredential(Integer userId, String platform, String account, Boolean valid);

    /**
     * 根据加密信息 ID 获取密码
     * @param userId 用户 ID
     * @param encryptionId 加密信息 ID
     * @return 密码明文
     */
    String getPassword(Integer userId, Integer encryptionId) throws Exception;
}
