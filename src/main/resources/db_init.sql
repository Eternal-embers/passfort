DROP DATABASE IF EXISTS passfort;

CREATE DATABASE IF NOT EXISTS passfort
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE passfort;

-- 创建用户主表，存储用户的基本信息
CREATE TABLE users (
   user_id INT AUTO_INCREMENT PRIMARY KEY, -- 用户唯一标识，主键，自动递增
   email VARCHAR(128) UNIQUE DEFAULT NULL, -- 邮箱地址（唯一，用于邮箱注册）
   password_hash VARBINARY(128) NOT NULL, -- 密码哈希（存储哈希值和盐值的组合）
   created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 注册时间
   is_active TINYINT(1) DEFAULT 0, -- 账户是否激活（0：未激活，1：已激活）
   last_login_at DATETIME DEFAULT NULL, -- 最后一次登录时间
   failed_login_attempts INT DEFAULT 0, -- 连续失败的登录尝试次数
   lockout_until DATETIME DEFAULT NULL, -- 账户锁定时间
   last_password_update DATETIME DEFAULT CURRENT_TIMESTAMP -- 上一次密码更新时间
);

-- 创建第三方登录关联表，存储用户与第三方登录方式的关联信息
CREATE TABLE user_social_logins (
    login_id INT AUTO_INCREMENT PRIMARY KEY, -- 第三方登录关联唯一标识，主键，自动递增
    user_id INT NOT NULL, -- 用户ID，外键关联`users`表
    provider VARCHAR(50) NOT NULL, -- 第三方登录平台（如wechat、qq、alipay等）
    provider_user_id VARCHAR(255) NOT NULL, -- 第三方平台的用户ID
    access_token TEXT, -- 第三方平台的访问令牌
    refresh_token TEXT, -- 第三方平台的刷新令牌
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 关联时间
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- 最后更新时间
    UNIQUE KEY unique_social_login (provider, provider_user_id), -- 确保同一个第三方平台的用户ID是唯一的
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE -- 外键关联用户主表，用户删除时级联删除关联记录
);

-- 凭证加密信息表，将用于解密的密钥和iv存储在此表中
-- 允许删除的条件：没有credential表和credential_history表中的记录引用 credential_encryption 表中的记录
CREATE TABLE credential_encryption (
    encryption_id INT AUTO_INCREMENT PRIMARY KEY, -- 加密信息的唯一标识，自增主键
    iv BINARY(16) NOT NULL, -- 初始化向量（IV），用于加密算法，长度为16字节
    secret_key BINARY(32) NOT NULL -- 密钥，用于加密算法，长度为32字节
);

-- 凭证表，存储用户的凭证信息（如账号和加密后的密码）
CREATE TABLE credential (
    credential_id INT AUTO_INCREMENT PRIMARY KEY, -- 凭证的唯一标识，自增主键
    user_id INT NOT NULL, -- 关联用户表的用户 ID
    encryption_id INT NOT NULL, -- 关联凭证加密表的加密信息 ID
    platform VARCHAR(255) NOT NULL, -- 凭证所属的平台（如网站或应用名称）
    account VARCHAR(255) NOT NULL, -- 用户在该平台上的账号
    encrypted_password VARBINARY(512) NOT NULL, -- 加密后的密码，最大长度为512字节
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 凭证创建时间，默认为当前时间
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- 凭证更新时间，自动更新为当前时间戳
    valid BOOLEAN DEFAULT TRUE, -- 凭证是否有效，默认为 TRUE
    UNIQUE (platform, account), -- 确保同一平台下账号的唯一性
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT, -- 外键约束，关联用户表，删除用户时需要先删除所有凭证
    FOREIGN KEY (encryption_id) REFERENCES credential_encryption(encryption_id) ON DELETE RESTRICT -- 外键约束，关联加密信息表，删除凭证加密信息前需要先删除凭证
);

-- 凭证历史表，记录凭证的历史变更信息
CREATE TABLE credential_history (
    history_id INT
        AUTO_INCREMENT PRIMARY KEY, -- 历史记录的唯一标识，自增主键
    credential_id INT NOT NULL, -- 关联凭证表的凭证 ID
    encrypted_password VARBINARY(255) NOT NULL, -- 历史版本的加密密码
    encryption_id INT NOT NULL, -- 关联凭证加密表的加密信息 ID
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 历史记录的创建时间，默认为当前时间
    FOREIGN KEY (credential_id) REFERENCES credential(credential_id) ON DELETE CASCADE, -- 外键约束，关联凭证表，凭证删除时级联删除历史记录
    FOREIGN KEY (encryption_id) REFERENCES credential_encryption(encryption_id) ON DELETE RESTRICT -- 外键约束，关联加密信息表，删除加密信息前需要先删除凭证历史记录
);

# 更新凭证密码时自动创建凭证历史记录
DELIMITER //

CREATE TRIGGER trg_credentials_update
    BEFORE UPDATE ON credential
    FOR EACH ROW
BEGIN
    -- 检查密码是否被更新
    IF OLD.encrypted_password != NEW.encrypted_password THEN
        -- 将旧的密码数据插入到credential_history表中
        INSERT INTO credential_history (credential_id, encrypted_password, encryption_id)
        VALUES (OLD.credential_id, OLD.encrypted_password, OLD.encryption_id);
    END IF;
END //

DELIMITER ;