package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    private Integer userId; // 用户唯一标识，主键，自动递增
    private String email; // 邮箱地址（唯一，用于邮箱注册）
    private byte[] passwordHash; // 密码哈希（存储哈希值和盐值的组合）
    private LocalDateTime createdAt; // 注册时间
    private Boolean isActive; // 账户是否激活（0：未激活，1：已激活）
    private LocalDateTime lastLoginAt; // 最后一次登录时间
    private Integer failedLoginAttempts; // 连续失败的登录尝试次数
    private LocalDateTime lockoutUntil; // 账户锁定时间
    private LocalDateTime lastPasswordUpdate; // 上一次更新时间
    private Boolean isTwoFactorAuthEnabled; // 是否开启双重认证
}
