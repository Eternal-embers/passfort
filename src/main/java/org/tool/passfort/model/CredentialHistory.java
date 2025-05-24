package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialHistory {
    private Integer historyId; // 历史记录的唯一标识，自增主键
    private Integer userId; // 关联用户表的用户 ID
    private Integer encryptionId; // 关联凭证加密表的加密信息 ID
    private String platform; // 凭证所属的平台（如网站或应用名称）
    private String account; // 用户在该平台上的账号
    private LocalDateTime createdAt; // 历史记录的创建时间，默认为当前时间
}