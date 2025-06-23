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
import org.tool.passfort.exception.FrequentVerificationCodeRequestException;
import org.tool.passfort.exception.InvalidEmailException;
import org.tool.passfort.exception.UserNotFoundException;
import org.tool.passfort.model.ClientDeviceInfo;
import org.tool.passfort.service.EmailService;
import org.tool.passfort.service.UserService;
import org.tool.passfort.util.redis.RedisUtil;
import org.apache.commons.validator.routines.EmailValidator;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/mail")
@SuppressWarnings("rawtypes") // 消除ApiResponse的原始类型警告
public class EmailController {
    private static final Logger logger = LoggerFactory.getLogger(EmailController.class);
    private final EmailService emailService;
    private final RedisUtil redisUtil;
    private final UserService userService;

    // 常量
    private final String VERIFICATION_CODE_PREFIX = "verificationCode:"; // 验证码的 redis 键前缀
    private final String VERIFICATION_CODE_REQUEST_TIME_PREFIX = "verificationCodeRequestTime:"; // 最新的验证码请求时间的 redis 键前缀
    private final long VERIFICATION_CODE_EXPIRE_TIME = 300; // 验证码有效期，5 分钟

    @Autowired
    public EmailController(EmailService emailService, RedisUtil redisUtil, UserService userService) {
        this.emailService = emailService;
        this.redisUtil = redisUtil;
        this.userService = userService;
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

    // 设置模板参数
    private Map<String, Object> getTemplateVariables(ClientDeviceInfo deviceInfo, String verificationCode, String operationType) {
        Map<String, Object> templateVariables = new HashMap<>();
        String operationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        templateVariables.put("operationType", operationType);
        templateVariables.put("ipAddress", deviceInfo.getIpAddress());
        templateVariables.put("deviceType", deviceInfo.getDeviceType());
        templateVariables.put("osName", deviceInfo.getOsName());
        templateVariables.put("osVersion", deviceInfo.getOsVersion());
        templateVariables.put("browserName", deviceInfo.getBrowserName());
        templateVariables.put("browserVersion", deviceInfo.getBrowserVersion());
        templateVariables.put("operationTime", operationTime);
        templateVariables.put("verificationCode", verificationCode);

        return templateVariables;
    }

    /**
     * 处理未注册的账号的邮箱验证，发送邮箱验证码，重新请求至少需要间隔一分钟
     * @param request 包含 JWT interceptor 解析的用户信息
     * @param data 请求体中需要包含 email
     * @return 验证码和验证码的 redis 键
     * @throws FrequentVerificationCodeRequestException 验证码请求间隔异常，疑似恶意攻击
     */
    @PostMapping("/register_verify")
    public ApiResponse sendRegisterEmail(HttpServletRequest request, @RequestBody Map<String, String> data) throws FrequentVerificationCodeRequestException, InvalidEmailException {
        // 验证邮箱格式
        String email = data.get("email");
        EmailValidator validator = EmailValidator.getInstance();
        if (!validator.isValid(email)) {
            throw new InvalidEmailException("Invalid email format");
        }

        // 获取客户端设备信息
        ClientDeviceInfo deviceInfo = (ClientDeviceInfo) request.getAttribute("clientDeviceInfo");

        // 检查是否间隔超过一分钟再请求验证码，防止恶意攻击
        String lastRequestTimeKey =  VERIFICATION_CODE_REQUEST_TIME_PREFIX + email;
        String operationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        long remainingExpireTime = redisUtil.getExpire(lastRequestTimeKey); // 剩余过期时间（秒)
        if(remainingExpireTime > VERIFICATION_CODE_EXPIRE_TIME - 60){
            logger.error("Request verification code too frequently for email: {} from IP address: {}",  email, deviceInfo.getIpAddress());//验证码请求间隔异常，疑似恶意攻击
            throw new FrequentVerificationCodeRequestException(email, deviceInfo.getIpAddress());
        }
        redisUtil.set(lastRequestTimeKey, operationTime, VERIFICATION_CODE_EXPIRE_TIME, TimeUnit.SECONDS); // 记录最新的验证码请求时间

        // 将验证码存储到 redis
        String verificationCode = getVerificationCode(); // 生成验证码
        String codeKey = VERIFICATION_CODE_PREFIX + ":" + UUID.randomUUID();
        String verificationInfo = email + ":" + verificationCode;// 验证信息的格式为"邮箱:验证码"
        redisUtil.set(codeKey, verificationInfo , VERIFICATION_CODE_EXPIRE_TIME, TimeUnit.SECONDS);

        // 设置模板参数
        Map<String, Object> templateVariables = getTemplateVariables(deviceInfo, verificationCode, "register");

        // 发送邮件
        emailService.sendEmailWithTemplate(email, "PassFort 邮箱验证", "auth.html", templateVariables);

        return ApiResponse.success(codeKey);
    }

    /**
     * 处理已经注册的账号的邮箱验证，发送邮箱验证码，重新请求至少需要间隔一分钟
     * @param request 包含 JWT interceptor 解析的用户信息
     * @param data 请求体中需要包含 email 和 operationType
     * @return 验证码和验证码的 redis 键
     * @throws FrequentVerificationCodeRequestException 验证码请求间隔异常，疑似恶意攻击
     * @throws UserNotFoundException 未注册的邮箱发起邮箱验证
     */
    @PostMapping("/verify")
    public ApiResponse sendVerificationEmail(HttpServletRequest request, @RequestBody Map<String, String> data) throws FrequentVerificationCodeRequestException, UserNotFoundException, InvalidEmailException {
        // 获取请求参数
        String email = data.get("email");
        String operationType = data.get("operationType");
        Integer userId = userService.getUserId(email);

        if(userId == null) {
            logger.error("Unregistered email: {} request verification code", email); // 异常行为，未注册的邮箱发起邮箱验证
            throw new UserNotFoundException(email);
        }

        // 获取客户端设备信息
        ClientDeviceInfo deviceInfo = (ClientDeviceInfo) request.getAttribute("clientDeviceInfo");

        // 检查是否间隔超过一分钟再请求验证码，防止恶意攻击
        String lastRequestTimeKey =  VERIFICATION_CODE_REQUEST_TIME_PREFIX + email;
        String operationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        long remainingExpireTime = redisUtil.getExpire(lastRequestTimeKey); // 剩余过期时间（秒)
        if(remainingExpireTime > VERIFICATION_CODE_EXPIRE_TIME - 60){
            logger.error("Request verification code too frequently for email: {} from IP address: {}",  email, deviceInfo.getIpAddress());//验证码请求间隔异常，疑似恶意攻击
            throw new FrequentVerificationCodeRequestException(email, deviceInfo.getIpAddress());
        }
        redisUtil.set(lastRequestTimeKey, operationTime, VERIFICATION_CODE_EXPIRE_TIME, TimeUnit.SECONDS); // 记录最新的验证码请求时间

        // 将验证码存储到 redis
        String verificationCode = getVerificationCode(); // 生成验证码
        String codeKey = VERIFICATION_CODE_PREFIX  + userId + ":" + UUID.randomUUID();
        String verificationInfo = email + ":" + verificationCode;// 验证信息的格式为"邮箱:验证码"
        redisUtil.set(codeKey, verificationInfo , VERIFICATION_CODE_EXPIRE_TIME, TimeUnit.SECONDS); // 将验证码存储到 redis

        // 设置模板参数
        Map<String, Object> templateVariables = getTemplateVariables(deviceInfo, verificationCode, operationType);

        // 发送邮件
        emailService.sendEmailWithTemplate(email, "PassFort 邮箱验证", "auth.html", templateVariables);

        return ApiResponse.success(codeKey);
    }
}
