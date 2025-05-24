package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.tool.passfort.model.CredentialHistory;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface CredentialHistoryMapper {

    /**
     * 多参数查询
     * @param userId
     * @param encryptionId
     * @param platform
     * @param account
     * @return
     */
    List<CredentialHistory> selectByParams(@Param("userId") Integer userId,
                                           @Param("encryptionId") Integer encryptionId,
                                           @Param("platform") String platform,
                                           @Param("account") String account);

    /**
     * 根据历史ID查询
     * @param historyId
     * @return
     */
    CredentialHistory selectByHistoryId(@Param("historyId") Integer historyId);

    /**
     * 删除指定用户id，具体account和platform的某个创建时间前的所有历史记录
     * @param userId
     * @param account
     * @param platform
     * @param createdAt
     */
    void deleteByUserIdAccountPlatformAndCreatedAtBefore(@Param("userId") Integer userId,
                                                         @Param("account") String account,
                                                         @Param("platform") String platform,
                                                         @Param("createdAt") LocalDateTime createdAt);
}