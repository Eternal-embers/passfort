package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.tool.passfort.model.CredentialChangeLog;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface CredentialChangeLogMapper {

    // 根据历史ID、用户ID、操作类型、操作描述创建日志
    void createLog(@Param("historyId") Integer historyId,
                   @Param("userId") Integer userId,
                   @Param("operationType") String operationType,
                   @Param("description") String description);

    // 多参数查询，参数包括用户ID和操作类型
    List<CredentialChangeLog> queryByUserIdAndOperationType(@Param("userId") Integer userId,
                                                            @Param("operationType") String operationType);

    // 查询某时间前的日志
    List<CredentialChangeLog> queryByTimeBefore(@Param("userId") Integer userId,
                                                @Param("time") LocalDateTime time);

    // 查询某时间后的日志
    List<CredentialChangeLog> queryByTimeAfter(@Param("userId") Integer userId,
                                               @Param("time") LocalDateTime time);
}