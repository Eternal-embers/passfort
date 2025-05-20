package org.tool.passfort.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.tool.passfort.exception.*;
import org.tool.passfort.mapper.UserMapper;
import org.tool.passfort.model.LoginResponse;
import org.tool.passfort.model.User;
import org.tool.passfort.service.UserService;
import org.tool.passfort.util.jwt.JwtUtil;
import org.tool.passfort.util.secure.PasswordHasher;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
@Transactional
public class UserServiceImpl implements UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final UserMapper userMapper;
    private final PasswordHasher passwordHasher;
    private final JwtUtil jwtUtil;

    @Autowired
    public UserServiceImpl(UserMapper userMapper, PasswordHasher passwordHasher, JwtUtil jwtUtil) {
        this.userMapper = userMapper;
        this.passwordHasher = passwordHasher;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 使用默认邮箱注册方式注册账号，根据抛出的不同异常方式判定注册失败的原因
     * @param email 邮箱地址
     * @param password 密码
     */
    @Override
    public void registerUser(String email, String password) throws PasswordHashingException, DatabaseOperationException, EmailAlreadyRegisteredException {
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
     */
    @Override
    public LoginResponse loginUser(String email, String password) throws AccountNotActiveException, AccountLockedException, UserNotFoundException, VerifyPasswordFailedException, PasswordInvalidException {
        //检查帐号是否激活
        boolean isActive = userMapper.isActive(email);
        if(!isActive){
            logger.error("account not active for email: {}", email);
            throw new AccountNotActiveException(email);
        }

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

            //创建 claims
            Map<String, String> claims = new HashMap<>();
            claims.put("isAdmin", user.getIsAdmin().toString());

            String token =  jwtUtil.createToken(userId.toString(), claims, 3600);//1小时过期

            return new LoginResponse(userId, token, claims);
        }

        logger.error("password invalid for email: {}", email);

        throw new PasswordInvalidException(email);
    }


    /**
     * 重置用户密码
     * @param email 邮箱地址
     * @param newPassword 新密码
     */
    @Override
    public boolean resetPassword(String email, String newPassword) {
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

        //如果密码与上一次不同
        if(!isPasswordValid) {
            //创建新的密码哈希值
            byte[] newPasswordHash;
            try {
                newPasswordHash = passwordHasher.hashPassword(newPassword);
            } catch (Exception e) {
                logger.error("failed to hash password when reset password for email: {}", email);
                return false;
            }

            //更新密码
            userMapper.resetPassword(email, newPasswordHash);
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

    @Override
    public String refreshToken(String token) {
        return "";
    }
}
