package org.tool.passfort.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.tool.passfort.exception.*;
import org.tool.passfort.dto.LoginResponse;
import org.tool.passfort.service.UserService;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.util.jwt.JwtUtil;
import org.tool.passfort.util.redis.RedisUtil;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;

    @Autowired
    public UserController(UserService userService, JwtUtil jwtUtil, RedisUtil redisUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.redisUtil = redisUtil;
    }

    /**
     * 注册用户
     * @param request 请求中需要包含 email, password
     * @throws DatabaseOperationException 数据库操作异常
     * @throws PasswordHashingException 密码哈希异常
     * @throws EmailAlreadyRegisteredException 邮箱已注册
     */
    @PostMapping("/register")
    public ApiResponse register(@RequestBody Map<String, String> request) throws DatabaseOperationException, PasswordHashingException, EmailAlreadyRegisteredException {
        String email = request.get("email");
        String password = request.get("password");

        userService.registerUser(email, password);

        return ApiResponse.success(email + " register success");
    }

    //激活帐号
    @PostMapping("/activate")
    public ApiResponse activate(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        userService.activateUser(email);

        return ApiResponse.success("Activate " + email + " success");
    }

    /**
     * 用户登录
     * @param request 请求中需要包含 email, password, 如果开启了双重认证则还需要包含 code, codeKey
     * @return 返回数据包括 access token, refresh token的信息和用户信息
     * @throws UserNotFoundException 用户不存在
     * @throws AccountLockedException 用户被冻结
     * @throws VerifyPasswordFailedException 密码验证程序出现错误
     * @throws AccountNotActiveException 用户未激活
     * @throws PasswordInvalidException 密码无效
     * @throws VerificationCodeErrorException 验证码错误
     * @throws VerificationCodeExpireException 验证码过期
     */
    @PostMapping("/login")
    public ApiResponse login(@RequestBody Map<String, String> request) throws UserNotFoundException, AccountLockedException, VerifyPasswordFailedException, AccountNotActiveException, PasswordInvalidException, VerificationCodeErrorException, VerificationCodeExpireException {
        String email = request.get("email");
        String password = request.get("password");
        String code = request.get("code");
        String codeKey = request.get("codeKey");

        // 验证密码
        LoginResponse loginResponse = userService.loginUser(email, password);

        // 默认开启双重认证 - 邮箱验证
        boolean isTwoFactorAuthEnabled = userService.isTwoFactorAuthEnabled(email);
        if (isTwoFactorAuthEnabled) {
            userService.verify(code, codeKey);
        }

        return ApiResponse.success(loginResponse);
    }

    //查询用户是否在登录状态
    @GetMapping("/login_status")
    public ApiResponse isLogin (HttpServletRequest request) {
        // 解析 jwt token
        String token = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        DecodedJWT decodedJWT = jwtUtil.verifyToken(token);

        // 获取 JWT 的格式化过期时间
        Date expirationDate = decodedJWT.getExpiresAt();
        Instant instant = expirationDate.toInstant();
        ZoneId zoneId = ZoneId.systemDefault();
        LocalDateTime localDateTime = LocalDateTime.ofInstant(instant, zoneId);
        String formattedExpirationTime = localDateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // 检查帐号是否被冻结
        boolean isLocked = userService.isAccountLocked(request.getAttribute("email").toString());
        String email = decodedJWT.getClaim("email").asString();
        if(isLocked) {
            LocalDateTime lockoutUntil = userService.getLockoutUntil(email);
            return ApiResponse.failure(403, "Account " + email + " is locked. Lockout until: " + lockoutUntil);
        }

        // 持有合法 JWT 令牌
        return ApiResponse.success("The user is currently logged in. The identity will expire at " + formattedExpirationTime + ".");
    }

    /**
     * 重置密码, 冻结的账户仍然可以重置密码
     * @param request 请求对象
     * @param data 包含 email 和 newPassword 两个字段
     * @return 返回重置密码的结果
     * @throws UnauthorizedException 非法操作，使用合法token尝试修改其他人的密码会触发此异常
     * @throws PasswordRepeatException 新密码与旧密码相同
     */
    @PostMapping("/reset_password")
    public ApiResponse resetPassword(HttpServletRequest request, @RequestBody Map<String, String> data) throws UnauthorizedException, PasswordRepeatException {
        String emailFromToken = (String) request.getAttribute("email");
        String email = data.get("email");
        String newPassword = data.get("newPassword");

        // 进行权限校验
        if (!emailFromToken.equals(email)) {
            // 获取请求来源的IP地址
            String ipAddress = request.getRemoteAddr();
            // 获取User-Agent信息
            String userAgent = request.getHeader("User-Agent");

            logger.error("Unauthorized attempt to reset password for user: {} from IP address: {}. Requested email: {}. User-Agent: {}",
                    emailFromToken, ipAddress, email, userAgent);
            throw new UnauthorizedException("Unauthorized operation");//非法操作
        }

        boolean result = userService.resetPassword(email, newPassword);

        if(result) {
            return ApiResponse.success("Reset password success");
        }

        return ApiResponse.failure(500, "Internal server error");
    }

    @PostMapping("/lock_account")
    public ApiResponse lockAccount(HttpServletRequest request, String email, LocalDateTime lockoutUntil){
        // 检查 token 包含 admin 权限
        String token = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        DecodedJWT decodedJWT = jwtUtil.verifyToken(token);

        boolean result = userService.lockAccount(email, lockoutUntil);

        if (result) {
            return ApiResponse.success("Account lock operation successful. The account with email " + email + " has been locked until " + lockoutUntil + ".");
        }

        return ApiResponse.failure(500, "Internal server error");
    }

    @PostMapping("/logout")
    public ApiResponse logout(HttpServletRequest request) {
        String refreshToken = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        userService.logout(refreshToken);

        return ApiResponse.success("Logout success");
    }

    /**
     * 获取新的 access token
     * @param request 请求对象，需要在 Authorization 头部携带 refresh token
     * @return 返回新的 access token
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    @PostMapping("/new_access_token")
    public ApiResponse getNewAccessToken(HttpServletRequest request) throws AuthenticationExpiredException {
        String refreshToken = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        String newAccessToken = userService.getNewAccessToken(refreshToken);

        return ApiResponse.success(newAccessToken);
    }

    /**
     * 获取新的 refresh token
     * @param request 请求对象，需要在 Authorization 头部携带 refresh token
     * @return 返回新的 refresh token
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    @PostMapping("/new_refresh_token")
    public ApiResponse getNewRefreshToken(HttpServletRequest request) throws AuthenticationExpiredException {
        String refreshToken = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        String newRefreshToken = userService.getNewRefreshToken(refreshToken);

        return ApiResponse.success(newRefreshToken);
    }

    // 查询 refresh token 是否即将过期
    @GetMapping("/refresh_token_expiring_soon")
    public ApiResponse isRefreshTokenExpiringSoon(HttpServletRequest request) {
        String refreshToken = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        boolean isExpiringSoon = userService.isRefreshTokenExpiringSoon(refreshToken);
        return ApiResponse.success(isExpiringSoon);
    }
}
