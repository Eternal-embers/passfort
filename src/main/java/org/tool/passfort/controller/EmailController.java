package org.tool.passfort.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.dto.VerifyResponse;
import org.tool.passfort.exception.FrequentVerificationCodeRequestException;
import org.tool.passfort.service.EmailService;
import org.tool.passfort.service.UserService;
import org.tool.passfort.util.jwt.JwtUtil;
import org.tool.passfort.util.redis.RedisUtil;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/mail")
public class EmailController {
    private static final Logger logger = LoggerFactory.getLogger(EmailController.class);
    private final EmailService emailService;
    private final UserService userService;
    private final RedisUtil redisUtil;
    private final JwtUtil jwtUtil;

    // 常量
    private final String VERIFICATION_CODE_PREFIX = "verificationCode:"; // 验证码的 redis 键前缀
    private final String VERIFICATION_CODE_REQUEST_TIME_PREFIX = "verificationCodeRequestTime:"; // 最新的验证码请求时间的 redis 键前缀
    private final long VERIFICATION_CODE_EXPIRE_TIME = 300; // 验证码有效期，5 分钟

    @Autowired
    public EmailController(EmailService emailService, UserService userService, RedisUtil redisUtil, JwtUtil jwtUtil) {
        this.emailService = emailService;
        this.userService = userService;
        this.redisUtil = redisUtil;
        this.jwtUtil = jwtUtil;
    }

    // 生成6位随机验证码，包含数字和大小写字母
    private String getVerificationCode() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        char[] code = new char[6];
        for (int i = 0; i < 6; i++) {
            code[i] = characters.charAt(ThreadLocalRandom.current().nextInt(characters.length()));
        }
        return new String(code);
    }

    /**
     * 发送邮箱验证码，重新请求至少需要间隔一分钟
     * @param request
     * @param data 请求体中需要包含 email 和 operationType
     * @return
     */
    @PostMapping("/verify")
    public ApiResponse sendVerificationEmail(HttpServletRequest request, @RequestBody Map<String, String> data) throws FrequentVerificationCodeRequestException {
        String email = data.get("email");
        String operationType = data.get("operationType");

        int userId = userService.getUserId(email);

        // 收集请求信息用于邮件提示
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String operationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // 检查是否间隔超过一分钟再请求验证码，防止恶意攻击
        String lastRequestTimeKey =  VERIFICATION_CODE_REQUEST_TIME_PREFIX + userId;
        long remaingExpireTime = redisUtil.getExpire(lastRequestTimeKey); // 剩余过期时间（秒)
        if(remaingExpireTime > VERIFICATION_CODE_EXPIRE_TIME - 60){
            logger.error("Request verification code too frequently for email: {} from IP address: {}. User-Agent: {}",  email, ipAddress, userAgent);//验证码请求间隔异常，疑似恶意攻击
            throw new FrequentVerificationCodeRequestException(email, ipAddress, userAgent);
        }

        // 生成验证码
        String verificationCode = getVerificationCode();

        // 将验证码存储到 redis， 并记录发起请求的时间
        String codeKey = VERIFICATION_CODE_PREFIX  + userId + ":" + UUID.randomUUID();
        String verificationInfo = email + ":" + verificationCode;// 验证信息的格式为"邮箱:验证码"
        redisUtil.setString(codeKey, verificationInfo , VERIFICATION_CODE_EXPIRE_TIME, TimeUnit.SECONDS);

        // 记录最新的验证码请求时间，防止恶意攻击
        redisUtil.setString(lastRequestTimeKey, operationTime, VERIFICATION_CODE_EXPIRE_TIME, TimeUnit.SECONDS);

        Map<String, Object> templateVariables = new HashMap<>();
        String templatePath = "auth.html";

        templateVariables.put("operationType", operationType);
        templateVariables.put("deviceInfo", userAgent);
        templateVariables.put("ipAddress", ipAddress);
        templateVariables.put("operationTime", operationTime);
        templateVariables.put("verificationCode", verificationCode);
        emailService.sendEmailWithTemplate(email, "PassFort 邮箱验证", templatePath, templateVariables);

        return ApiResponse.success(new VerifyResponse(verificationCode, codeKey));
    }
}
