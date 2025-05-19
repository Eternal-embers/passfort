package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserSocialLogin {
    private Integer loginId; // 第三方登录关联唯一标识，主键，自动递增
    private Integer userId; // 用户ID，外键关联`users`表
    private String provider; // 第三方登录平台（如wechat、qq、alipay等）
    private String providerUserId; // 第三方平台的用户ID
    private String accessToken; // 第三方平台的访问令牌
    private String refreshToken; // 第三方平台的刷新令牌
    private LocalDateTime createdAt; // 关联时间
    private LocalDateTime updatedAt; // 最后更新时间
}
