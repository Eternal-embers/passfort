package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialChangeLog {
    private Integer logId; // 变更记录的唯一标识，自增主键
    private Integer historyId; // 关联凭证历史表的记录 ID
    private Integer userId; // 执行操作的用户 ID（操作者）
    private String operationType; // 操作类型：新增、更新、删除等，使用字符串存储
    private LocalDateTime operationTime; // 操作发生的时间，默认为当前时间
    private String description; // 操作描述，用于记录操作的详细信息（如变更原因等）
}
