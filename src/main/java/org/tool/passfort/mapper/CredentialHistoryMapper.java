package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.tool.passfort.model.CredentialHistory;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface CredentialHistoryMapper {

    List<CredentialHistory> getAccountHistory(@Param("userId") Integer userId, @Param("credentialId") Integer credentialId);

    /**
     * 多参数查询
     * @param userId
     * @param platform
     * @param account
     * @return
     */
    List<CredentialHistory> selectByParams(@Param("userId") Integer userId,
                                           @Param("platform") String platform,
                                           @Param("account") String account);

    /**
     * 根据historyId获取 encriptionId
     */
    Integer selectEncryptionIdByHistoryId(@Param("historyId") Integer historyId);

    void deleteByHistoryId(@Param("historyId") Integer historyId);

    /**
     * 删除指定用户id，具体account和platform的某个创建时间前的所有历史记录
     * @param userId 用户 ID
     * @param credentialId 凭证 ID
     * @param createdAt 创建时间
     */
    void deleteByCreatedAtBefore(@Param("userId") Integer userId,
                                 @Param("credentialId") Integer credentialId,
                                 @Param("createdAt") LocalDateTime createdAt);
}