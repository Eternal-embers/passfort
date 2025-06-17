package org.tool.passfort.controller;

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.model.CredentialHistory;
import org.tool.passfort.service.CredentialHistoryService;
import org.tool.passfort.service.EmailService;
import org.tool.passfort.util.encrypt.AesUtil;
import org.tool.passfort.util.encrypt.ShuffleEncryption;
import org.tool.passfort.util.qr.QRCodeUtil;

import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/credential_history")
public class CredentialHistoryController {
    private final CredentialHistoryService credentialHistoryService;
    private final AesUtil aesUtil;
    private final EmailService emailService;

    private final static int[] SHUFFLE_ORDER = {7, 2, 5, 0, 3, 6, 1, 4};

    @Autowired
    public CredentialHistoryController(CredentialHistoryService credentialHistoryService, AesUtil aesUtil, EmailService emailService) {
        this.credentialHistoryService = credentialHistoryService;
        this.aesUtil = aesUtil;
        this.emailService = emailService;
    }

    /**
     * 获取指定凭证的所有历史变更记录
     * @param request 请求体中需要包含 userId 和 credentialId
     * @return 指定凭证的所有历史记录
     */
    @PostMapping("/get")
    public ApiResponse getAccountHistory(HttpServletRequest request, @RequestBody Map<String, String> data) {
        String userId = (String) request.getAttribute("userId");
        int credentialId = Integer.parseInt(data.get("credentialId"));
        List<CredentialHistory> credentialHistories = credentialHistoryService.getAccountHistory(Integer.parseInt(userId), credentialId);

        return ApiResponse.success(credentialHistories);
    }

    /**
     * 获取指定历史记录的密码
     * @param request 请求体中需要包含 userId 和 historyId
     * @return
     * @throws Exception
     */
    @PostMapping("/view")
    public ApiResponse getPassword(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        int historyId = Integer.parseInt(data.get("historyId"));
        String password = credentialHistoryService.getPassword(Integer.parseInt(userId), historyId);

        // 对密码进行混淆加密
        byte[] encryptedPassword = aesUtil.encrypt(password);//iv, key, encryptedPassword的组合, 64字节
        byte[] shuffledEncryptedPassword = ShuffleEncryption.shuffleEncrypt(encryptedPassword, SHUFFLE_ORDER);

        return ApiResponse.success(shuffledEncryptedPassword);
    }

    /**
     * 发送邮件，邮件中包含密码信息的二维码
     * @param request 请求对象
     * @param data 请求体中需要包含 historyId
     * @return 返回信息 ID
     */
    @PostMapping("/view/qr")
    public ApiResponse viewPasswordQR(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String email = (String) request.getAttribute("email");
        String historyId = data.get("historyId");
        String password = credentialHistoryService.getPassword(Integer.valueOf(userId), Integer.valueOf(historyId));// 获取密码

        // 收集请求信息用于邮件提示
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String operationTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // 生成二维码
        String qrImage = QRCodeUtil.generateQRCode(password, 200, 200, "PNG",  Color.BLACK, Color.WHITE, ErrorCorrectionLevel.H, 2);

        // 生成邮件模板
        Map<String, Object> templateVariables = new HashMap<>();
        String templatePath = "qr.html";
        String infoId = UUID.randomUUID().toString();
        templateVariables.put("infoId", infoId);
        templateVariables.put("deviceInfo", userAgent);
        templateVariables.put("ipAddress", ipAddress);
        templateVariables.put("operationTime", operationTime);
        templateVariables.put("qrImage", "data:image/png;base64," + qrImage);
        emailService.sendEmailWithTemplate(email, "PassFort 二维码",  templatePath, templateVariables);

        return ApiResponse.success(infoId);
    }

    /**
     * 删除指定的某个历史记录
     * @param request 请求体中需要包含 userId 和 historyId
     * @return 删除历史记录的结果
     */
    @PostMapping("/delete")
    public ApiResponse deleteAccountHistory(HttpServletRequest request, @RequestBody Map<String, String> data) {
        String userId = (String) request.getAttribute("userId");
        int historyId = Integer.parseInt(data.get("historyId"));

        credentialHistoryService.deleteAccountHistory(Integer.parseInt(userId), historyId);

        return ApiResponse.success("Delete history[id: " + historyId + "] success");
    }

    /**
     * 删除指定日期前的所有历史记录
     * @param data 请求体中需要包含 credentialId 和 createdAt
     * @return 删除历史记录的结果
     */
    @PostMapping("/delete/before")
    public ApiResponse deleteAccountHistoryBefore(HttpServletRequest request, @RequestBody Map<String, String> data) {
        String userId = (String) request.getAttribute("userId");
        int credentialId = Integer.parseInt(data.get("credentialId"));
        LocalDateTime createdAt = LocalDateTime.parse(data.get("createdAt"));

        credentialHistoryService.deleteAccountHistory(Integer.parseInt(userId), credentialId, createdAt);

        return ApiResponse.success("Delete history[credentialId: " + credentialId + "] before " + createdAt + " success");
    }
}
