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
   permission_hash VARBINARY(128) DEFAULT NULL, -- 权限口令哈希（存储权限口令的哈希值）
   created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 注册时间
   is_active TINYINT(1) DEFAULT 0, -- 账户是否激活（0：未激活，1：已激活）
   last_login_at DATETIME DEFAULT NULL, -- 最后一次登录时间
   failed_login_attempts INT DEFAULT 0, -- 连续失败的登录尝试次数
   lockout_until DATETIME DEFAULT NULL, -- 账户锁定时间
   last_password_update DATETIME DEFAULT CURRENT_TIMESTAMP, -- 上一次密码更新时间
   is_two_factor_auth_enabled TINYINT(1) DEFAULT 1 -- 是否开启双重认证（0：未开启，1：已开启）
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
    secret_key BINARY(32) NOT NULL, -- 密钥，用于加密算法，长度为32字节
    encrypted_password VARBINARY(256) NOT NULL -- 加密后的密码，256字节
);

-- 凭证表，存储用户的凭证信息（如账号和加密后的密码）
CREATE TABLE credential (
    credential_id INT AUTO_INCREMENT PRIMARY KEY, -- 凭证的唯一标识，自增主键
    user_id INT NOT NULL, -- 关联用户表的用户 ID
    encryption_id INT NOT NULL, -- 关联凭证加密表的加密信息 ID
    platform VARCHAR(255) NOT NULL, -- 凭证所属的平台（如网站或应用名称）
    account VARCHAR(255) NOT NULL, -- 用户在该平台上的账号
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 凭证创建时间，默认为当前时间
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- 凭证更新时间，自动更新为当前时间戳
    valid BOOLEAN DEFAULT TRUE, -- 凭证是否有效，默认为 TRUE
    UNIQUE (platform, account), -- 确保同一平台下账号的唯一性
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT, -- 关联用户表，删除用户时需要先删除所有凭证
    FOREIGN KEY (encryption_id) REFERENCES credential_encryption(encryption_id) ON DELETE RESTRICT -- 关联加密信息表，删除凭证加密信息前需要先删除相关联的凭证
);

-- 凭证历史表，记录凭证的历史变更信息
CREATE TABLE credential_history (
    history_id INT
        AUTO_INCREMENT PRIMARY KEY, -- 历史记录的唯一标识，自增主键
    credential_id INT NOT NULL, -- 凭证ID
    user_id INT NOT NULL, -- 关联用户表的用户 ID
    encryption_id INT NOT NULL, -- 关联凭证加密表的加密信息 ID
    platform VARCHAR(255) NOT NULL, -- 凭证所属的平台（如网站或应用名称）
    account VARCHAR(255) NOT NULL, -- 用户在该平台上的账号
    operation_type VARCHAR(20) NOT NULL, -- 操作类型
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 历史记录的创建时间，默认为当前时间
    FOREIGN KEY (credential_id) REFERENCES  credential(credential_id),
    FOREIGN KEY (encryption_id) REFERENCES credential_encryption(encryption_id) ON DELETE RESTRICT -- 关联加密信息表, 删除凭证加密信息前需要先删除相关联的凭证历史
);

DELIMITER //

CREATE TRIGGER trg_credential_before_update
    BEFORE UPDATE ON credential
    FOR EACH ROW
BEGIN
    DECLARE v_operation_type VARCHAR(20) DEFAULT 'update';
    DECLARE v_field_name VARCHAR(20) DEFAULT '';

    -- 检查 encryption_id 是否发生变化
    IF OLD.encryption_id != NEW.encryption_id THEN
        SET v_field_name = CONCAT(v_field_name, 'password,');
    END IF;

    -- 检查 platform 是否发生变化
    IF OLD.platform != NEW.platform THEN
        SET v_field_name = CONCAT(v_field_name, 'platform,');
    END IF;

    -- 检查 account 是否发生变化
    IF OLD.account != NEW.account THEN
        SET v_field_name = CONCAT(v_field_name, 'account,');
    END IF;

    -- 检查 valid 是否发生变化
    IF OLD.valid != NEW.valid THEN
        SET v_field_name = CONCAT(v_field_name, 'valid,');
    END IF;

    -- 去掉最后一个逗号
    SET v_field_name = TRIM(TRAILING ',' FROM v_field_name);

    -- 如果有字段发生变化，则拼接操作类型
    IF v_field_name != '' THEN
        SET v_operation_type = CONCAT(v_operation_type, '-', v_field_name);
    END IF;

    -- 将旧记录插入到 credential_history 表中
    INSERT INTO credential_history (
        credential_id,
        user_id,
        encryption_id,
        platform,
        account,
        operation_type
    ) VALUES (
        OLD.credential_id,
        OLD.user_id,
        OLD.encryption_id,
        OLD.platform,
        OLD.account,
        v_operation_type
    );
END //

DELIMITER ;