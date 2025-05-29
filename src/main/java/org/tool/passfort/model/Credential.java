package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Credential {
    private Integer credentialId; // 凭证的唯一标识，自增主键
    private Integer userId; // 关联用户表的用户 ID
    private Integer encryptionId; // 关联凭证加密表的加密信息 ID
    private String platform; // 凭证所属的平台（如网站或应用名称）
    private String account; // 用户在该平台上的账号
    private LocalDateTime createdAt; // 凭证创建时间，默认为当前时间
    private LocalDateTime updatedAt; // 凭证更新时间，自动更新为当前时间戳
    private Boolean valid; // 凭证是否有效，默认为 TRUE

    public Credential(Integer userId, Integer encryptionId, String platform, String account) {
        this.userId = userId;
        this.encryptionId = encryptionId;
        this.platform = platform;
        this.account = account;
    }
}
