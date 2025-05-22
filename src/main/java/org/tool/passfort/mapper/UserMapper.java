package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.*;
import org.tool.passfort.model.User;

import java.time.LocalDateTime;

@Mapper
public interface UserMapper {
    /**
     * 检查邮箱是否已注册
     * @param email 邮箱地址
     * @return 如果邮箱已注册返回 true，否则返回 false
     */
    @Select("SELECT COUNT(*) FROM users WHERE email = #{email}")
    boolean isEmailRegistered(@Param("email") String email);

    /**
     * 用户注册
     * @param email 邮箱地址
     * @param passwordHash 密码哈希值
     * @return 影响的行数
     */
    @Insert("INSERT INTO users (email, password_hash) " +
            "VALUES (#{email}, #{passwordHash})")
    int registerUser(@Param("email") String email, @Param("passwordHash") byte[] passwordHash);

    /**
     * 检查账号是否锁定
     * @param email 邮箱地址
     * @return 如果账号锁定返回 true，否则返回 false
     */
    @Select("SELECT lockout_until IS NOT NULL AND lockout_until > NOW() FROM users WHERE email = #{email}")
    boolean isAccountLocked(@Param("email") String email);

    /**
     * 获取账号锁定截止时间
     * @param email 邮箱地址
     * @return 账号锁定截止时间
     */
    @Select("SELECT lockout_until from users WHERE email = #{email}")
    LocalDateTime getLockoutUntil(@Param("email") String email);

    @Select("SELECT * FROM users WHERE user_id = #{userId}")
    User getUserById(@Param("userId") Integer userId);

    /**
     * 根据邮箱获取用户信息
     * @param email 邮箱地址
     * @return 用户对象
     */
    @Select("SELECT * FROM users WHERE email = #{email}")
    User getUserByEmail(@Param("email") String email);

    /**
     * 更新用户的最后登录时间，并清零失败尝试次数
     * @param email 邮箱地址
     */
    @Update("UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0 WHERE email = #{email}")
    void updateLastLogin(@Param("email") String email);

    /**
     * 增加用户的失败登录次数
     * @param email 邮箱地址
     */
    @Update("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE email = #{email}")
    void incrementFailedLoginAttempts(@Param("email") String email);

    /**
     * 获取用户的失败登录次数
     * @param email 邮箱地址
     * @return 失败登录次数
     */
    @Select("SELECT failed_login_attempts FROM users WHERE email = #{email}")
    Integer getFailedLoginAttempts(@Param("email") String email);

    /**
     * 重置用户的失败登录次数
     * @param email 邮箱地址
     */
    @Update("UPDATE users SET failed_login_attempts = 0 WHERE email = #{email}")
    void resetFailedLoginAttempts(@Param("email") String email);

    /**
     * 锁定账户
     * @param email 邮箱地址
     * @param lockoutUntil 锁定截止时间
     */
    @Update("UPDATE users SET lockout_until = #{lockoutUntil}, failed_login_attempts = 0 WHERE email = #{email}")
    void lockAccount(@Param("email") String email, @Param("lockoutUntil") LocalDateTime lockoutUntil);

    /**
     * 检查用户是否激活
     * @param email 邮箱地址
     * @return 如果用户激活返回 true，否则返回 false
     */
    @Select("SELECT is_active FROM users WHERE email = #{email}")
    boolean isActive(@Param("email") String email);

    /**
     * 激活用户账户
     * @param email 邮箱地址
     */
    @Update("UPDATE users SET is_active = 1 WHERE email = #{email}")
    void activateUser(@Param("email") String email);

    /**
     * 重置用户密码
     * @param email 邮箱地址
     * @param passwordHash 新的密码哈希值
     */
    @Update("UPDATE users SET password_hash = #{passwordHash}, last_password_update = NOW() WHERE email = #{email}")
    void resetPassword(@Param("email") String email, @Param("passwordHash") byte[] passwordHash);
}
