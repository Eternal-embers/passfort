package org.tool.passfort.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.exception.AuthenticationExpiredException;
import org.tool.passfort.service.EmailService;
import org.tool.passfort.util.jwt.JwtUtil;
import org.tool.passfort.util.redis.RedisUtil;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@RestController
@RequestMapping("/api/email")
public class EmailController {
    private final EmailService emailService;
    private final RedisUtil redisUtil;
    private final JwtUtil jwtUtil;

    @Autowired
    public EmailController(EmailService emailService, RedisUtil redisUtil, JwtUtil jwtUtil) {
        this.emailService = emailService;
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
     * 发送邮箱验证码，请求需要携带合法token(access token 或 refresh token)
     * @param request
     * @param data
     * @return
     */
    @PostMapping("/verify")
    public ApiResponse sendVerificationEmail(HttpServletRequest request, @RequestBody Map<String, String> data) throws AuthenticationExpiredException {
        String token = request.getHeader("Authorization").substring(7); // 去掉 "Bearer " 前缀

        // 解析 token
        DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
        String key = decodedJWT.getClaim("key").asString();
        String to = decodedJWT.getClaim("email").asString();

        // 检查 token 是否过期
        if (redisUtil.isExpire(key)) {
            throw new AuthenticationExpiredException("Refresh token has expired.");
        }

        // 获取请求的信息
        String operationType = data.get("operationType");
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String operationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // 生成验证码
        String verificationCode = getVerificationCode();

        Map<String, Object> templateVariables = new HashMap<>();
        String templatePath = "auth.html";

        templateVariables.put("operationType", operationType);
        templateVariables.put("deviceInfo", userAgent);
        templateVariables.put("ipAddress", ipAddress);
        templateVariables.put("operationTime", operationTime);
        templateVariables.put("verificationCode", verificationCode);
        emailService.sendEmailWithTemplate(to, "PassFort 邮箱验证", templatePath, templateVariables);

        return ApiResponse.success(verificationCode);
    }
}
