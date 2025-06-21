package org.tool.passfort.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.tool.passfort.exception.*;
import org.tool.passfort.dto.LoginResponse;
import org.tool.passfort.model.ActivationInformation;
import org.tool.passfort.model.ClientDeviceInfo;
import org.tool.passfort.service.UserService;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.service.UserVerificationService;
import org.tool.passfort.util.jwt.JwtUtil;
import org.tool.passfort.util.secure.PasswordGenerator;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/user")
@SuppressWarnings("rawtypes") // 消除ApiResponse的原始类型警告
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    private final UserVerificationService userVerificationService;
    private final JwtUtil jwtUtil;

    @Autowired
    public UserController(UserService userService, UserVerificationService userVerificationService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.userVerificationService = userVerificationService;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 注册用户
     * @param request 请求中需要包含 email, password
     * @throws DatabaseOperationException 数据库操作异常
     * @throws PasswordHashingException 密码哈希异常
     * @throws EmailAlreadyRegisteredException 邮箱已注册
     */
    @PostMapping("/register")
    public ApiResponse register(@RequestBody Map<String, String> request) throws DatabaseOperationException, PasswordHashingException, EmailAlreadyRegisteredException, VerificationCodeErrorException, VerificationCodeExpireException {
        String email = request.get("email");
        String password = request.get("password");
        String code = request.get("code");
        String codeKey = request.get("codeKey");

        // 验证验证码
        userService.verify(email, code, codeKey);

        // 注册用户
        userService.registerUser(email, password);

        return ApiResponse.success(email + " register success");
    }

    /**
     * 创建 Https Only Cookie
     * @param name cookie名称
     * @param value cookie值
     * @param maxAge 有效期（秒）
     * @param path cookie路径，即path所在的url都会携带此Cookie，以客户端的url为准
     * @return 返回创建的Cookie
     */
    private Cookie createCookie(String name, String value, int maxAge, String path){
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true); // 设置为 HttpOnly，防止通过 JavaScript 访问
        cookie.setSecure(true); // 设置为 Secure，仅在 HTTPS 连接中传输
        cookie.setMaxAge(maxAge); // 设置有效期
        cookie.setPath(path); // 设置路径

        return cookie;
    }

    /**
     * 密码验证，用于重置密码时验证身份
     * @param request 请求中包含JWT interceptor 解析得到的用户信息
     * @param response 响应对象，用于设置验证cookie，cookie 的时效为10分钟，必须在10分钟内完成密码重置
     * @param data 请求体中需要包含 password
     * @throws VerifyPasswordFailedException 密码验证失败
     * @throws PasswordVerificationException 密码验证异常
     */
    @PostMapping("/password_verification")
    public ApiResponse passwordVerification(HttpServletRequest request, HttpServletResponse response, @RequestBody Map<String, String> data) throws VerifyPasswordFailedException, PasswordVerificationException {
        String email = (String) request.getAttribute("email");
        String password = data.get("password");
        userService.passwordVerification(email, password);

        // 验证通过，设置用户的密码验证通过的 cookie
        Cookie passwordVerificationCookie = createCookie("passwordVerification", "true", 60 * 10, "/");
        response.addCookie(passwordVerificationCookie);

        return ApiResponse.success("Password verification success");
    }

    /**
     * 生成身份验证请求，用于在 Cookie 中设置用户身份, 身份验证请求需要在 30 分钟内完成，否则此验证失效
     */
    @PostMapping("/generate_verification_request")
    public ApiResponse generateVerificationRequest(@RequestBody Map<String, String> data, HttpServletResponse response) {
        String email = data.get("email");

        Cookie verificationRequestCookie = createCookie("verificationRequest", email, 60 * 30, "/");
        response.addCookie(verificationRequestCookie);

        return ApiResponse.success("Generate verification request success");
    }

    /**
     * 恢复邮箱验证
     * @param request 请求中包含JWT interceptor 解析得到的用户信息
     * @param data 请求体中需要包含 verificationCode 和 codeKey
     * @throws VerificationCodeErrorException 抛出验证码异常则验证失败
     */
    @PostMapping("/verify/recovery_email")
    public ApiResponse recoveryEmailVerification(HttpServletRequest request, HttpServletResponse response, @RequestBody Map<String, String> data) throws VerificationCodeErrorException, VerificationCodeExpireException {
        Integer userId = Integer.parseInt((String) request.getAttribute("userId"));
        String verificationCode = data.get("verificationCode");
        String codeKey = data.get("codeKey");

        userVerificationService.recoveryEmailVerification(userId, verificationCode, codeKey);

        // 验证通过，设置用户的恢复邮箱验证通过的 cookie, 30 分钟内必须完成其他验证，否则此验证失效
        Cookie recoveryEmailVerificationCookie = createCookie("recoveryEmailVerification", "true", 60 * 30, "/");
        response.addCookie(recoveryEmailVerificationCookie);

        return ApiResponse.success("Recovery email verification success");
    }

    /**
     * 安全问题验证
     * @param request 请求中包含JWT interceptor 解析得到的用户信息
     * @param data 请求体中需要包含 securityAnswer1, securityAnswer2, securityAnswer3
     * @throws SecurityQuestionVerificationException 抛出安全问题验证异常则验证失败
     */
    @PostMapping("verify/security_questions")
    public ApiResponse securityQuestionVerification(HttpServletRequest request, HttpServletResponse response, @RequestBody Map<String, String> data) throws SecurityQuestionVerificationException {
        Integer userId = Integer.parseInt((String) request.getAttribute("userId"));
        String securityAnswer1 = data.get("securityAnswer1");
        String securityAnswer2 = data.get("securityAnswer2");
        String securityAnswer3 = data.get("securityAnswer3");

        userVerificationService.securityQuestionVerification(userId, securityAnswer1, securityAnswer2, securityAnswer3);

        // 验证通过，设置用户的安全问题验证通过的 cookie, 20 分钟内必须完成其他验证，否则此验证失效
        Cookie securityQuestionVerificationCookie = createCookie("securityQuestionVerification", "true", 60 * 20, "/");
        response.addCookie(securityQuestionVerificationCookie);

        return ApiResponse.success("Security question verification success");
    }

    /**
     * 个人信息验证
     * @param request 请求中包含JWT interceptor 解析得到的用户信息
     * @param data 请求体中需要包含 fullName, idCardNumber, phoneNumber
     * @throws PersonalInfoVerificationException 抛出个人信息验证异常则验证失败
     */
    @PostMapping("verify/personal_info")
    public ApiResponse personalInfoVerification(HttpServletRequest request, HttpServletResponse response, @RequestBody Map<String, String> data) throws PersonalInfoVerificationException {
        Integer userId = Integer.parseInt((String) request.getAttribute("userId"));
        String fullName = data.get("fullName");
        String idCardNumber = data.get("idCardNumber");
        String phoneNumber = data.get("phoneNumber");

        userVerificationService.personalInfoVerification(userId, fullName, idCardNumber, phoneNumber);

        // 验证通过，设置用户的个人信息验证通过的 cookie, 15 分钟内必须完成其他验证，否则此验证失效
        Cookie personalInfoVerificationCookie = createCookie("personalInfoVerification", "true", 60 * 15, "/");
        response.addCookie(personalInfoVerificationCookie);

        return ApiResponse.success("Personal info verification success");
    }

    /**
     * 其他可选信息验证
     * @param request 请求中包含JWT interceptor 解析得到的用户信息
     * @param data 请求体中需要包含 highSchoolName, hometown, occupation, motherFullName, fatherFullName
     * @throws OtherInfoVerificationException 抛出其他信息验证异常则验证失败
     */
    @PostMapping("verify/other_info")
    public ApiResponse otherInfoVerification(HttpServletRequest request, HttpServletResponse response, @RequestBody Map<String, String> data) throws OtherInfoVerificationException {
        Integer userId = Integer.parseInt((String) request.getAttribute("userId"));
        String highSchoolName = data.get("highSchoolName");
        String hometown = data.get("hometown");
        String occupation = data.get("occupation");
        String motherFullName = data.get("motherFullName");
        String fatherFullName = data.get("fatherFullName");

        // 检查参数是否为空，如果为空则设置为空字符串
        if (highSchoolName == null) highSchoolName = "";
        if (hometown == null) hometown = "";
        if (occupation == null) occupation = "";
        if (motherFullName == null) motherFullName = "";
        if (fatherFullName == null) fatherFullName = "";

        userVerificationService.otherInfoVerification(userId, highSchoolName, hometown, occupation, motherFullName, fatherFullName);

        // 验证通过，设置用户的其他信息验证通过的 cookie, 5 分钟内必须提交，否则此验证失效
        Cookie otherInfoVerificationCookie = createCookie("otherInfoVerification", "true", 60 * 5,"/");
        response.addCookie(otherInfoVerificationCookie);

        return ApiResponse.success("Other info verification success");
    }

    /**
     *  激活账号, 根据用户填写的身份验证信息激活账号
     * @param request 请求中包含JWT interceptor 解析得到的用户信息
     * @param activationInformation 账户激活信息
     */
    @PostMapping("/activate")
    public ApiResponse activate(HttpServletRequest request, @RequestBody ActivationInformation activationInformation) throws VerificationCodeExpireException, VerificationCodeErrorException {
        // 创建用户验证信息，包括验证和插入操作
        userVerificationService.createUserVerification(activationInformation);

        // 激活账号
        String email = (String) request.getAttribute("email");
        userService.activateUser(email);

        return ApiResponse.success("Activate account" + email + "success");
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
    public ApiResponse login(HttpServletResponse response, @RequestBody Map<String, String> request) throws UserNotFoundException, AccountLockedException, VerifyPasswordFailedException, AccountNotActiveException, PasswordInvalidException, VerificationCodeErrorException, VerificationCodeExpireException {
        String email = request.get("email");
        String password = request.get("password");
        String code = request.get("code");
        String codeKey = request.get("codeKey");

        // 验证密码
        LoginResponse loginResponse = userService.loginUser(email, password);

        // 默认开启双重认证 - 邮箱验证
        boolean isTwoFactorAuthEnabled = userService.isTwoFactorAuthEnabled(email);
        if (isTwoFactorAuthEnabled) {
            userService.verify(email, code, codeKey);
        }

        // 将 refreshToken 信息写入到 HttpOnly 的 Cookie 中, Cookie 有效期为 7 天
        String refreshToken = userService.getRefreshTokenByUserId(loginResponse.getUserId(),  loginResponse.getRefreshTokenKey()); // 从 redis 中获取 refresh token
        Cookie refreshTokenCookie = createCookie("refreshToken", refreshToken, 60 * 60 * 24 * 7, "/");
        response.addCookie(refreshTokenCookie);

        return ApiResponse.success(loginResponse);
    }

    //查询用户是否在登录状态
    @GetMapping("/login_status")
    public ApiResponse isLogin (HttpServletRequest request) {
        // 解析 jwt token
        String token = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
        String email = decodedJWT.getClaim("email").asString();

        // 获取 JWT 的格式化过期时间
        Date expirationDate = decodedJWT.getExpiresAt();
        Instant instant = expirationDate.toInstant();
        ZoneId zoneId = ZoneId.systemDefault();
        LocalDateTime localDateTime = LocalDateTime.ofInstant(instant, zoneId);
        String formattedExpirationTime = localDateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // 检查帐号是否被冻结
        boolean isLocked = userService.isAccountLocked(email);
        if(isLocked) {
            LocalDateTime lockoutUntil = userService.getLockoutUntil(email);
            return ApiResponse.failure(403, "Account " + email + " is locked. Lockout until: " + lockoutUntil);
        }

        // 持有合法 JWT 令牌
        return ApiResponse.success("The user is currently logged in. The identity will expire at " + formattedExpirationTime + ".");
    }

    private boolean isEqualTrue(String s) {
        return s != null && s.equals("true");
    }

    /**
     * 是否完成多因素身份验证
     * @param request Http 请求携带多因素身份验证的 cookie
     * @return 返回是否完成多因素身份验证
     */
    private boolean isMFAVerified(HttpServletRequest request){
        /* 检查是否完成身份验证 */
        boolean isAuthorized = false;// 是否授权
        String isRecoveryEmailVerification = getCookieValue(request, "recoveryEmailVerification");
        String isSecurityQuestionVerification = getCookieValue(request, "securityQuestionVerification");
        String isPersonalInfoVerification = getCookieValue(request, "personalInfoVerification");
        String isOtherInfoVerification = getCookieValue(request, "otherInfoVerification");
        if(isEqualTrue(isRecoveryEmailVerification) &&
                isEqualTrue(isSecurityQuestionVerification) &&
                isEqualTrue(isPersonalInfoVerification) &&
                isEqualTrue(isOtherInfoVerification)) {
            isAuthorized = true;
        }

        return isAuthorized;
    }

    /**
     * 由系统对账户进行重置密码，需要完成验证：恢复邮箱验证 + 安全问题验证 + 个人信息验证 + 其他信息验证
     * 此方法无需要经过 JWT interceptor 验证，因为此方法是由系统调用的，不需要验证用户身份
     * @param request 请求对象, 附带身份验证 cookie
     * @return 返回系统生成的密码
     * @throws UnauthorizedException 非法操作，未初始化一个身份验证请求或者未完成身份验证
     * @throws PasswordRepeatException 新密码与旧密码相同
     */
    @PostMapping("/reset_password")
    public ApiResponse resetPassword(HttpServletRequest request) throws UnauthorizedException, PasswordRepeatException {
        // 检查身份验证请求Cookie
        String verificationRequest = getCookieValue(request, "verificationRequest"); // 此cookie值为用户邮箱
        if (verificationRequest == null) {
            logger.error("Unauthorized operation, the system has not initiated an identity verification request");
            throw new UnauthorizedException("Unauthorized operation"); // 非法的操作，系统未发起身份验证请求
        }

        /* 检查是否完成身份验证 */
        boolean isAuthorized = isMFAVerified(request);
        if(!isAuthorized) {
            logger.error("Unauthorized operation, the user has not completed identity verification");
            throw new UnauthorizedException("Unauthorized operation"); // 非法的操作，未完成身份验证没有重置权限
        }

        // 系统生成重置密码
        String newPassword = PasswordGenerator.generateSecurePassword(32);

        // 重置密码
        userService.resetPassword(verificationRequest, newPassword);

        return ApiResponse.success(newPassword);
    }

    /**
     * 用户登录状态下重置密码, 冻结的账户仍然可以重置密码
     * @param request 请求对象
     * @param data 包含 email 和 newPassword 两个字段
     * @return 返回重置密码的结果
     * @throws UnauthorizedException 非法操作，使用合法token尝试修改其他人的密码会触发此异常, 或者未完成身份验证
     * @throws PasswordRepeatException 新密码与旧密码相同
     */
    @PostMapping("/update_password")
    public ApiResponse updatePassword(HttpServletRequest request, @RequestBody Map<String, String> data) throws UnauthorizedException, PasswordRepeatException {
        String emailFromToken = (String) request.getAttribute("email");
        String email = data.get("email");
        String newPassword = data.get("newPassword");

        // 检查 token 的用户与重置密码的账户是否一致
        if (!emailFromToken.equals(email)) {
            // 获取设备信息拦截器中获取 ip 地址
            ClientDeviceInfo deviceInfo = (ClientDeviceInfo)request.getAttribute("clientDeviceInfo");
            String ipAddress = deviceInfo.getIpAddress();

            logger.error("Unauthorized attempt to reset password for user: {} from IP address: {}. Requested email: {}. Device info: {}",
                    emailFromToken, ipAddress, email, deviceInfo);
            throw new UnauthorizedException("Unauthorized operation");//非法操作
        }

        /*
            检查是否完成身份验证，存在两种密码验证方式
            1. 密码验证
            2. 恢复邮箱验证 + 安全问题验证 + 个人信息验证 + 其他信息验证
         */
        boolean isAuthorized = false;// 是否授权
        // 检查是否完成密码验证
        String isPasswordVerification  = getCookieValue(request, "passwordVerification");
        if (isEqualTrue(isPasswordVerification)) {
            isAuthorized = true;
        }

        // 检查是否完成多因素身份验证
        if(isMFAVerified(request)) {
            isAuthorized = true;
        }

        if(!isAuthorized) {
            logger.error("Unauthorized update password for email: {}, the user has not completed identity verification", email);
            throw new UnauthorizedException("Unauthorized update password for email: " + email);
        }

        userService.resetPassword(email, newPassword);

        return ApiResponse.success("Reset password success");
    }

    @PostMapping("/lock_account")
    public ApiResponse lockAccount(HttpServletRequest request, String email, LocalDateTime lockoutUntil){
        // 检查 token
        String token = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
        String jwtEmail = decodedJWT.getClaim("email").asString();

        if(!jwtEmail.equals(email)) {
            return ApiResponse.failure(403, "Unauthorized operation");
        }

        boolean result = userService.lockAccount(email, lockoutUntil);

        if (result) {
            return ApiResponse.success("Account lock operation successful. The account with email " + email + " has been locked until " + lockoutUntil + ".");
        }

        return ApiResponse.failure(500, "Internal server error");
    }

    /**
     * 用户注销, 使当前会话的 refresh token 失效
     * @param request 请求对象，在 cookie 中携带了 refresh token
     */
    @PostMapping("/logout")
    public ApiResponse logout(HttpServletRequest request) {
        String refreshToken = getCookieValue(request, "refreshToken");
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
        // 从 Cookie 中获取 refreshToken
        String refreshToken = getCookieValue(request, "refreshToken");

        String newAccessToken = userService.getNewAccessToken(refreshToken);

        String encodedAccessToken = userService.encrypt(newAccessToken);

        return ApiResponse.success(encodedAccessToken);
    }

    /**
     * 获取 cookie 的值
     * @param request 请求对象
     * @param cookieName cookie 名称
     * @return 返回 cookie 的值
     */
    private String getCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * 获取新的 refresh token
     * @param request 请求对象，携带 refreshToken 的cookie
     * @return 返回新的 refresh token
     * @throws AuthenticationExpiredException 刷新令牌已过期
     */
    @PostMapping("/new_refresh_token")
    public ApiResponse getNewRefreshToken(HttpServletRequest request, HttpServletResponse response) throws AuthenticationExpiredException {
        // 从 Cookie 中获取 refreshToken
        String refreshToken = getCookieValue(request, "refreshToken");

        String newRefreshToken = userService.getNewRefreshToken(refreshToken);

        // 创建新的 refreshToken Cookie
        Cookie newRefreshTokenCookie = new Cookie("refreshToken", newRefreshToken);
        newRefreshTokenCookie.setHttpOnly(true); // 设置为 HttpOnly，防止通过 JavaScript 访问
        newRefreshTokenCookie.setSecure(true); // 设置为 Secure，仅在 HTTPS 连接中传输
        newRefreshTokenCookie.setMaxAge(60 * 60 * 24 * 7); // 设置过期时间为 7 天
        newRefreshTokenCookie.setPath("/"); // 设置路径为根路径，确保在整个应用中有效
        response.addCookie(newRefreshTokenCookie); // 将新的 refreshToken Cookie 添加到响应中

        return ApiResponse.success("New refresh token successfully");
    }

    // 查询 refresh token 是否即将过期
    @GetMapping("/refresh_token_expiring_soon")
    public ApiResponse isRefreshTokenExpiringSoon(HttpServletRequest request) {
        String refreshToken = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀
        boolean isExpiringSoon = userService.isRefreshTokenExpiringSoon(refreshToken);
        return ApiResponse.success(isExpiringSoon);
    }
}
