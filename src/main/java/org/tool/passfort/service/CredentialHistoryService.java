package org.tool.passfort.service;

import org.tool.passfort.model.CredentialHistory;

import java.time.LocalDateTime;
import java.util.List;

public interface CredentialHistoryService {
    /**
     * 获取凭证的所有历史变更记录
     * @param userId 用户 ID
     * @param credentialId 凭证 ID
     * @return 凭证的所有历史记录
     */
    List<CredentialHistory> getAccountHistory(int userId, int credentialId);

    /**
     * 获取凭证的某条历史变更记录对应的密码
     * @param userId 用户 ID
     * @param historyId 历史记录 ID
     * @return 凭证的某条历史记录对应的密码
     */
    String getPassword(int userId, int historyId) throws Exception;


    /**
     * 删除指定的某个历史记录
     * @param userId 用户 ID
     * @param historyId 历史记录 ID
     */
    void deleteAccountHistory(int userId, int historyId);

    /**
     * 删除指定凭证的某个创建时间前的所有历史记录
     * @param userId 用户 ID
     * @param credentialId 凭证 ID
     * @param createdAt 创建时间
     */
    void deleteAccountHistory(int userId, int credentialId, LocalDateTime createdAt);
}