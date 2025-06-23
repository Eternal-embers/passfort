package org.tool.passfort.service.impl;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.validator.routines.EmailValidator;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.tool.passfort.exception.*;
import org.tool.passfort.mapper.UserMapper;
import org.tool.passfort.dto.LoginResponse;
import org.tool.passfort.model.User;
import org.tool.passfort.service.UserService;
import org.tool.passfort.util.encrypt.AesUtil;
import org.tool.passfort.util.encrypt.ShuffleEncryption;
import org.tool.passfort.util.jwt.JwtUtil;
import org.tool.passfort.util.redis.RedisUtil;
import org.tool.passfort.util.secure.PasswordHasher;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@Transactional(rollbackFor = DatabaseOperationException.class) // 开启事务，并在发生 DatabaseOperationException 异常时回滚
public class UserServiceImpl implements UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final UserMapper userMapper;
    private final PasswordHasher passwordHasher;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;
    private final AesUtil aesUtil;

    // 常量
    private static final String REFRESH_TOKEN_KEY_PREFIX = "refreshToken:";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 900; // 15分钟
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 604800; // 7天
    private static final long LOCKOUT_TIME = 1800; // 30分钟
    private static final long REFRESH_TOKEN_EXPIRING_SOON_THRESHOLD = 3600; // 1小时
    private final static int[] SHUFFLE_ORDER = {2, 14, 15, 6, 8, 9, 12, 4, 10, 11, 3, 13, 0, 7, 1, 5};

    @Autowired
    public UserServiceImpl(UserMapper userMapper, PasswordHasher passwordHasher, JwtUtil jwtUtil, RedisUtil redisUtil, AesUtil aesUtil) {
        this.userMapper = userMapper;
        this.passwordHasher = passwordHasher;
        this.jwtUtil = jwtUtil;
        this.redisUtil = redisUtil;
        this.aesUtil = aesUtil;
    }

    /**
     * AES加密并分片混淆
     * @param data 待加密数据字符串
     * @return BASE64编码后的加密数据
     */
    public String encrypt(String data) {
        byte[] encryptedData;
        try {
            encryptedData = aesUtil.encrypt(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // 分片混淆
        byte[] shuffledEncryptedData = ShuffleEncryption.shuffleEncrypt(encryptedData, SHUFFLE_ORDER);

        // BASE64编码
        return Base64.getEncoder().encodeToString(shuffledEncryptedData);
    }

    public String decrypt(String data) throws Exception {
        byte[] shuffledEncryptedData = Base64.getDecoder().decode(data);
        byte[] encryptedData = ShuffleEncryption.shuffleDecrypt(shuffledEncryptedData, SHUFFLE_ORDER);

        return aesUtil.decrypt(encryptedData);
    }

    /**
     * 使用默认邮箱注册方式注册账号，根据抛出的不同异常方式判定注册失败的原因
     * @param email 邮箱地址
     * @param password 密码
     * @throws PasswordHashingException 密码哈希处理失败
     * @throws DatabaseOperationException 数据库操作失败
     * @throws EmailAlreadyRegisteredException 邮箱已注册
     */
    @Override
    public void registerUser(@NotNull String email, @NotNull String password) throws PasswordHashingException, DatabaseOperationException, EmailAlreadyRegisteredException {
        //检查邮箱是否被注册
        boolean isRegistered = userMapper.isEmailRegistered(email);

        //如果邮箱未被注册
        if(!isRegistered){
            //对密码进行哈希处理
            byte[] passwordHash;
            try {
                passwordHash = passwordHasher.hashPassword(password);
            } catch (Exception e) {
                logger.error("failed to hash password for email: {}", email);
                throw new PasswordHashingException(email, e);
            }

            //注册用户
            int rowsAffected = userMapper.registerUser(email, passwordHash);
            if(rowsAffected != 1) {
                logger.error("failed to register user for email: {}", email);
                throw new DatabaseOperationException(email, "failed to register user");
            }
        } else {
            // 邮箱已经被注册
            logger.error("email already registered: {}", email);
            throw new EmailAlreadyRegisteredException(email);
        }
    }

    /**
     * 默认邮箱方式登录账号，
     * 根据抛出的异常决定登录失败的原因，如果密码错误则返回空字符串
     * @param email 邮箱
     * @param password 密码明文
     * @return JWT token
     * @throws AccountNotActiveException 账号未激活
     * @throws AccountLockedException 账号已锁定
     * @throws UserNotFoundException 用户不存在
     * @throws VerifyPasswordFailedException 验证密码时出现错误，每 5 次连续失败登录后锁定账户 30 分钟
     * @throws PasswordInvalidException 密码错误
     */
    @Override
    public LoginResponse loginUser(String email, String password) throws AccountLockedException, UserNotFoundException, VerifyPasswordFailedException, PasswordInvalidException {
        //检查帐号是否锁定
        boolean isLocked = userMapper.isAccountLocked(email);
        if(isLocked){
            LocalDateTime LockoutUntil = userMapper.getLockoutUntil(email);
            logger.error("account locked for email: {}, lockout until: {}", email, LockoutUntil);
            throw new AccountLockedException(email, LockoutUntil);
        }

        //获取用户信息
        User user = userMapper.getUserByEmail(email);
        if(user == null) {
            logger.error("user not found for email: {}", email);
            throw new UserNotFoundException(email);
        }

        //验证密码
        boolean isPasswordValid;
        try {
            isPasswordValid = passwordHasher.verifyPassword(password, user.getPasswordHash());
        } catch (Exception e) {
            //验证密码时出现错误
            logger.error("an error occurred while verifying password for email: {}", email);
            throw new VerifyPasswordFailedException(email);
        }

        //生成jwt token
        if(isPasswordValid) {
            // 用户id
            Integer userId = user.getUserId();

            // 创建 access token
            Map<String, String> accessClaims = new HashMap<>();
            accessClaims.put("email", user.getEmail());
            accessClaims.put("tokenType", "access");
            String accessToken =  jwtUtil.createToken(userId.toString(), accessClaims, ACCESS_TOKEN_EXPIRE_TIME);//15分钟过期

            // 创建 refresh token
            Map<String, String> refreshClaims = new HashMap<>();
            String uniqueSuffix = UUID.randomUUID().toString(); // 使用 UUID 生成唯一后缀
            String key = generateRefreshTokenKey(String.valueOf(userId), uniqueSuffix); // 生成 refresh token 的 key

            refreshClaims.put("email", user.getEmail());
            refreshClaims.put("tokenType", "refresh");
            refreshClaims.put("key", key);

            String refreshToken =  jwtUtil.createToken(userId.toString(), refreshClaims, REFRESH_TOKEN_EXPIRE_TIME);//7天过期

            // 存储Refresh token到redis
            redisUtil.set(key, refreshToken, REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.SECONDS);

            // 更新用户的最后登录时间
            userMapper.updateLastLogin(email);

            // 重置连续失败登录次数
            userMapper.resetFailedLoginAttempts(email);

            // 对 refreshToken 和 accessToken 进行加密处理
            String encryptedRefreshToken = encrypt(refreshToken);
            String encryptedAccessToken = encrypt(accessToken);

            return new LoginResponse(userId, encryptedAccessToken, key, encryptedRefreshToken, ACCESS_TOKEN_EXPIRE_TIME, REFRESH_TOKEN_EXPIRE_TIME);
        } else {
            // 更新连续失败登录次数
            userMapper.incrementFailedLoginAttempts(email);
            int failedLoginAttempts = userMapper.getFailedLoginAttempts(email);

            // 如果连续失败登录次数达到阈值的倍数，则锁定账户30分钟
            if(failedLoginAttempts % 10 == 0) {
                LocalDateTime lockoutUntil = LocalDateTime.now().plusSeconds(LOCKOUT_TIME);
                userMapper.lockAccount(email, lockoutUntil);
                // 记录日志，说明锁定账户的原因和具体操作
                logger.info("Account locked due to {} consecutive failed login attempts. Account: {}, lockout until: {}",
                        failedLoginAttempts, email, lockoutUntil);
            }
            logger.error("password invalid for email: {}, failed login attempts: {}", email, failedLoginAttempts);

            // 密码错误
            throw new PasswordInvalidException(email, failedLoginAttempts);
        }
    }

    /*
     * 根据用户Id获取Redis中最早的refreshToken
     */
    @Override
    public String getRefreshTokenByUserId(String refreshTokenKey) {
        return (String) redisUtil.get(refreshTokenKey);
    }

    /**
     * 检查验证码是否正确
     * @param code 验证码
     * @param codeKey redis key
     * @throws VerificationCodeExpireException 验证码过期
     * @throws VerificationCodeErrorException 验证码错误
     */
    @Override
    public void verify(String email, String code, String codeKey) throws VerificationCodeExpireException, VerificationCodeErrorException {
        //检查 codeKey 是否过期
        boolean isExpire = redisUtil.isExpire(codeKey);
        if(isExpire) {
            logger.error("verification code expired for codeKey: {}", codeKey);
            throw new VerificationCodeExpireException("Verification code expired");
        }

        //检查验证码是否正确
        String verificationInfo = (String) redisUtil.get(codeKey);// 验证信息的格式为"邮箱:验证码"
        if(!verificationInfo.equals(email + ":" + code)) {
            logger.error("verification code error for codeKey: {}", codeKey);
            throw new VerificationCodeErrorException("Verification code error");
        }
    }

    /**
     * 密码验证，用于重置密码时验证身份
     * @param email 邮箱地址
     * @param password 密码
     * @throws PasswordVerificationException 密码验证失败
     * @throws VerifyPasswordFailedException 验证密码时出现错误，每 5 次连续失败登录后锁定账户 30 分钟
     */
    public void passwordVerification(String email, String password) throws PasswordVerificationException, VerifyPasswordFailedException {
        boolean isPasswordValid;
        try {
            byte[] passwordHash = userMapper.getPasswordHash(email);
            isPasswordValid = passwordHasher.verifyPassword(password, passwordHash);
        } catch (Exception e) {
            //验证密码时出现错误
            logger.error("an error occurred while verifying password for email: {}", email);
            throw new VerifyPasswordFailedException(email);
        }

        // 更新 redis 中的密码验证错误次数
        Integer failedVerificationAttempts;
        if(!isPasswordValid) {
            logger.error("password verification failed for email: {}", email);

            String passwordVerificationKey = "passwordVerification:" + email;

            // 如果密码验证错误次数不存在，则创建并设置为 1
            if(!redisUtil.hasKey(passwordVerificationKey)) {
                redisUtil.set(passwordVerificationKey, 1, 30, TimeUnit.MINUTES); // 统计 30 分钟内的密码验证错误次数
                failedVerificationAttempts = 1;
            } else {
                // 如果密码验证错误次数存在，则获取并增加 1
                failedVerificationAttempts = (Integer) redisUtil.get(passwordVerificationKey);
                redisUtil.set(passwordVerificationKey, failedVerificationAttempts + 1, 30, TimeUnit.MINUTES); // 统计 30 分钟内的密码验证错误次数

                // 如果连续失败登录次数达到阈值的倍数，则锁定账户30分钟
                if(failedVerificationAttempts % 5 == 0) {
                    LocalDateTime lockoutUntil = LocalDateTime.now().plusSeconds(LOCKOUT_TIME);
                    userMapper.lockAccount(email, lockoutUntil);

                    logger.info("Account locked due to {} consecutive failed password verification attempts. Account: {}, lockout until: {}", failedVerificationAttempts, email, lockoutUntil);
                }
            }

            throw new PasswordVerificationException("Password verification failed", failedVerificationAttempts);
        }
    }

    /**
     * 重置用户密码
     * @param email 邮箱地址
     * @param newPassword 新密码
     * @throws PasswordRepeatException 新密码与旧密码相同
     */
    @Override
    public boolean resetPassword(String email, String newPassword) throws PasswordRepeatException {
        //获取用户信息
        User user = userMapper.getUserByEmail(email);

        //检查密码是否与当前密码重复
        boolean isPasswordValid;
        try {
            isPasswordValid = passwordHasher.verifyPassword(newPassword, user.getPasswordHash());
        } catch (Exception e) {
            logger.error("Failed to execute database operation while resetting password for email: {}", email);
            return false;
        }

        // 密码重复错误
        if(isPasswordValid) {
            logger.error("Password repeat for email: {}, old password: {}", email, newPassword);
            throw new PasswordRepeatException(email);
        }

        try {
            //创建新的密码哈希值
            byte[] newPasswordHash = passwordHasher.hashPassword(newPassword);
            //更新密码
            userMapper.resetPassword(email, newPasswordHash);
        } catch (Exception e) {
            logger.error("failed to hash password when reset password for email: {}", email);
            return false;
        }

        return true;
    }

    /**
     * 激活用户账户
     * @param email 邮箱地址
     * @return 如果激活成功返回 true，否则返回 false
     */
    @Override
    public boolean activateUser(String email) {
        boolean isActive = userMapper.isActive(email);
        if(!isActive) {
            try {
                userMapper.activateUser(email);
            } catch (Exception e) {
                logger.error("failed to activate user for email: {}", email);
                return false;
            }
        }
        return true;
    }

    /**
     * 锁定账户
     * @param email 邮箱地址
     * @param lockoutUntil 锁定截止时间
     * @return 如果锁定成功返回 true，否则返回 false
     */
    @Override
    public boolean lockAccount(String email, LocalDateTime lockoutUntil) {
        boolean isLocked = userMapper.isAccountLocked(email);
        if(!isLocked) {
            try {
                userMapper.lockAccount(email, lockoutUntil);
            } catch (Exception e) {
                logger.error("failed to lock account for email: {}", email);
                return false;
            }
        }
        return true;
    }

    /**
     * 检查账号是否锁定
     * @param email 邮箱地址
     * @return 如果账号锁定返回 true，否则返回 false
     */
    @Override
    public boolean isAccountLocked(String email) {
        return userMapper.isAccountLocked(email);
    }

    //获取账号锁定截止时间
    public LocalDateTime getLockoutUntil(String email) {
        return userMapper.getLockoutUntil(email);
    }

    /**
     * 使用合法且未过期的 refresh token 来获取新的 access token
     * @param refreshToken 刷新令牌
     * @return 新的访问令牌
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    @Override
    public String getNewAccessToken(String refreshToken) throws AuthenticationExpiredException {
        // 解析 token
        DecodedJWT decodedJWT = jwtUtil.verifyToken(refreshToken);
        String key = decodedJWT.getClaim("key").asString();
        String tokenType = decodedJWT.getClaim("tokenType").asString();
        String email = decodedJWT.getClaim("email").asString();
        String userId = decodedJWT.getSubject();

        // 检查 token 类型是否为 refresh
        if (!"refresh".equals(tokenType)) {
            throw new IllegalArgumentException("Invalid token type. Expected 'refresh'.");
        }

        // 检查 token 是否过期
        if (redisUtil.isExpire(key)) {
            throw new AuthenticationExpiredException("Refresh token has expired.");
        }

        // 创建新的 access token
        Map<String, String> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("tokenType", "access");

        return jwtUtil.createToken(userId, claims, ACCESS_TOKEN_EXPIRE_TIME); // 15分钟过期
    }

    /**
     * 生成新的 refresh token 的 key
     *
     * @param userId      用户 ID
     * @param uniqueSuffix 唯一后缀（如 UUID 或时间戳）
     * @return 生成的 Redis key
     */
    private String generateRefreshTokenKey(String userId, String uniqueSuffix) {
        return REFRESH_TOKEN_KEY_PREFIX + userId + ":" + uniqueSuffix;
    }

    /**
     * 使用合法且未过期的 refresh token 来获取新的 refresh token
     * @param refreshToken 刷新令牌
     * @return 新的刷新令牌
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    @Override
    public String getNewRefreshToken(String refreshToken) throws AuthenticationExpiredException, LoginRevocationException {
        // 解析 token
        DecodedJWT decodedJWT = jwtUtil.verifyToken(refreshToken);
        String tokenType = decodedJWT.getClaim("tokenType").asString();
        String email = decodedJWT.getClaim("email").asString();
        String oldKey = decodedJWT.getClaim("key").asString();
        String userId = decodedJWT.getSubject();

        // 检查 token 类型是否为 refresh
        if (!"refresh".equals(tokenType)) {
            throw new IllegalArgumentException("Invalid token type. Expected 'refresh'.");
        }

        // 检查 token 是否过期
        if (decodedJWT.getExpiresAt().before(new Date())) {
            throw new AuthenticationExpiredException("Refresh token has expired.");
        }

        // 检查 token 是否被吊销
        if (redisUtil.isExpire(oldKey)) {
            throw new LoginRevocationException("Refresh token has for " + email + " has been revoked. ");
        }

        // 删除旧的 refresh token
        redisUtil.delete(oldKey);

        // 创建新的 refresh token
        Map<String, String> refreshClaims = new HashMap<>();
        String uniqueSuffix = UUID.randomUUID().toString(); // 使用 UUID 生成唯一后缀
        String newKey = generateRefreshTokenKey(userId, uniqueSuffix); // 生成 refresh token 的 key

        refreshClaims.put("email", email);
        refreshClaims.put("tokenType", "refresh");
        refreshClaims.put("key", newKey);

        String newRefreshToken = jwtUtil.createToken(userId, refreshClaims, REFRESH_TOKEN_EXPIRE_TIME);
        logger.info("[GetNewRefreshToken] key: {}, email: {}, userId: {}", newKey, email, userId);

        // 存储Refresh token到redis
        redisUtil.set(newKey, newRefreshToken, REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.SECONDS);

        return newRefreshToken;
    }

    /**
     * 检查 refresh token 是否有效
     * @param refreshToken 刷新令牌
     * @return 如果 refresh token 有效返回 true，否则返回 false
     */
    public boolean isRefreshTokenValid(String refreshToken) {
        DecodedJWT decodedJWT = jwtUtil.verifyToken(refreshToken);
        String key = decodedJWT.getClaim("key").asString();

        return redisUtil.isExpire(key);
    }

    // 查询 refresh token 是否即将过期
    public boolean isRefreshTokenExpiringSoon(String refreshToken) {
        DecodedJWT decodedJWT = jwtUtil.verifyToken(refreshToken);
        String key = decodedJWT.getClaim("key").asString();

        long expireSeconds = redisUtil.getExpire(key);
        return expireSeconds <= REFRESH_TOKEN_EXPIRING_SOON_THRESHOLD;
    }

    /**
     * 注销用户，删除 refresh token
     * @param refreshToken 刷新令牌
     */
    @Override
    public void logout(String refreshToken) {
        // 检查 refresh token 是否有效
        DecodedJWT decodedJWT = jwtUtil.verifyToken(refreshToken);
        String oldKey = decodedJWT.getClaim("key").asString();
        boolean isExpire = redisUtil.isExpire(oldKey);

        if(isExpire) {
            logger.warn("[Logout] Refresh token has expired or has been revoked.");
        } else {
            // 删除 refresh token
            redisUtil.delete(oldKey);
        }
    }

    //查询帐号是否开启双重认证，默认开启
    public boolean isTwoFactorAuthEnabled(String email) {
        return userMapper.isTwoFactorAuthEnabled(email);
    }

    @Override
    public Integer getUserId(String email) {
        return userMapper.getUserId(email);
    }
}
