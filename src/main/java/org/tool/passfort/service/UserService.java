package org.tool.passfort.service;

import org.tool.passfort.exception.*;
import org.tool.passfort.dto.LoginResponse;

import java.time.LocalDateTime;

public interface UserService {
    /**
     * AES加密并分片混淆
     * @param data 待加密数据字符串
     * @return BASE64编码后的加密数据
     */
    String encrypt(String data);

    /**
     * 对AES加密并分片混淆的数据进行解密
     */
    String decrypt(String data) throws Exception;

    /**
     * 使用默认邮箱注册方式注册账号，根据抛出的不同异常方式判定注册失败的原因
     * @param email 邮箱地址
     * @param password 密码
     */
    void registerUser(String email, String password) throws PasswordHashingException, DatabaseOperationException, EmailAlreadyRegisteredException;

    /**
     * 默认邮箱方式登录账号，
     * 根据抛出的异常决定登录失败的原因，如果密码错误则返回空字符串
     * @param email 邮箱
     * @param password 密码明文
     * @return JWT token
     */
    LoginResponse loginUser(String email, String password) throws AccountLockedException, UserNotFoundException, VerifyPasswordFailedException, PasswordInvalidException;

    /*
     * 根据用户Id获取Redis中最早的refreshToken
     */
    String getRefreshTokenByUserId(String refreshTokenKey);

    /**
     * 检查验证码是否正确
     * @param code 验证码
     * @param codeKey redis key
     * @throws VerificationCodeExpireException 验证码过期
     * @throws VerificationCodeErrorException 验证码错误
     */
    void verify(String email, String code, String codeKey) throws VerificationCodeExpireException, VerificationCodeErrorException;

    /**
     * 密码验证，用于重置密码时验证身份
     * @param email 邮箱地址
     * @param password 密码
     * @throws PasswordVerificationException 密码验证失败
     * @throws VerifyPasswordFailedException 密码验证程序出现错误
     */
    void passwordVerification(String email, String password) throws PasswordVerificationException, VerifyPasswordFailedException;

    /**
     * 重置用户密码
     * @param email 邮箱地址
     * @param newPassword 新密码
     * @throws PasswordRepeatException 新密码与旧密码相同
     */
    boolean resetPassword(String email, String newPassword) throws PasswordRepeatException;

    /**
     * 激活用户账户
     * @param email 邮箱地址
     * @return 如果激活成功返回 true，否则返回 false
     */
    boolean activateUser(String email);

    /**
     * 锁定账户
     * @param email 邮箱地址
     * @param lockoutUntil 锁定截止时间
     * @return 如果锁定成功返回 true，否则返回 false
     */
    boolean lockAccount(String email, LocalDateTime lockoutUntil);

    /**
     * 检查账号是否锁定
     * @param email 邮箱地址
     * @return 如果账号锁定返回 true，否则返回 false
     */
    boolean isAccountLocked(String email);

    /**
     * 获取账号锁定截止时间
     * @param email 邮箱地址
     * @return 账号锁定截止时间
     */
    LocalDateTime getLockoutUntil(String email);

    /**
     * 获取新的 access token
     * @param refreshToken 刷新令牌
     * @return 新的 access token
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    String getNewAccessToken(String refreshToken) throws AuthenticationExpiredException;

    /**
     * 获取新的 refresh token
     * @param refreshToken 刷新令牌
     * @return 新的 refresh token
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    String getNewRefreshToken(String refreshToken) throws AuthenticationExpiredException, LoginRevocationException;

    /**
     * 检查 refresh token 是否有效
     * @param refreshToken 刷新令牌
     * @return 如果有效返回 true，否则返回 false
     */
    boolean isRefreshTokenValid(String refreshToken);

    /**
     * 检查 refresh token 是否即将过期
     * @param refreshToken 刷新令牌
     * @return 如果即将过期返回 true，否则返回 false
     */
    boolean isRefreshTokenExpiringSoon(String refreshToken);

    /**
     * 注销用户
     * @param refreshToken 刷新令牌
     */
    void logout(String refreshToken);

    /**
     * 检查用户是否开启了双重认证
     * @param email 邮箱地址
     * @return 如果开启了双重认证返回 true，否则返回 false
     */
    boolean isTwoFactorAuthEnabled(String email);

    /**
     * 获取用户 ID
     * @param email 邮箱地址
     * @return 用户 ID
     */
    Integer getUserId(String email);
}

