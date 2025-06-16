package org.tool.passfort.controller;

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.model.Credential;
import org.tool.passfort.service.CredentialService;
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
@RequestMapping("/credential")
public class CredentialController {
    private final CredentialService credentialService;
    private final AesUtil aesUtil;
    private final EmailService emailService;

    private final static int[] SHUFFLE_ORDER = {7, 2, 5, 0, 3, 6, 1, 4};

    @Autowired
    public CredentialController(CredentialService credentialService, AesUtil aesUtil, EmailService emailService) {
        this.credentialService = credentialService;
        this.aesUtil = aesUtil;
        this.emailService = emailService;
    }

    @PostMapping("/add")
    public ApiResponse addCredential(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String platform = data.get("platform");
        String account = data.get("account");
        String password = data.get("password");
        Credential credential = credentialService.createCredential(Integer.parseInt(userId), platform, account, password);

        return ApiResponse.success(credential);
    }

    @PostMapping("/get")
    public ApiResponse getCredentials(HttpServletRequest request) {
        String userId = (String) request.getAttribute("userId");
        List<Credential> credentials = credentialService.queryCredential(Integer.parseInt(userId), null, null, true);

        return ApiResponse.success(credentials);
    }

    @PostMapping("/view")
    public ApiResponse viewPassword(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String encryptionId = data.get("encryptionId");
        String password = credentialService.getPassword(Integer.valueOf(userId), Integer.valueOf(encryptionId));

        // 对密码进行混淆加密
        byte[] encryptedPassword = aesUtil.encrypt(password);//iv, key, encryptedPassword的组合, 64字节
        byte[] shuffledEncryptedPassword = ShuffleEncryption.shuffleEncrypt(encryptedPassword, SHUFFLE_ORDER);

        return ApiResponse.success(shuffledEncryptedPassword);
    }

    /**
     * 发送邮件，邮件中包含密码信息的二维码
     * @param request 请求对象
     * @param data 请求体中需要包含 encryptionId
     * @return 返回信息 ID
     */
    @PostMapping("/view/qr")
    public ApiResponse viewPasswordQR(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String email = (String) request.getAttribute("email");
        String encryptionId = data.get("encryptionId");
        String password = credentialService.getPassword(Integer.valueOf(userId), Integer.valueOf(encryptionId));// 获取密码

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

    @PostMapping("/update/account")
    public ApiResponse updateAccount(@RequestBody Map<String, String> data) {
        String credentialId = data.get("credentialId");
        String newAccount = data.get("newAccount");

        credentialService.updateAccount(Integer.parseInt(credentialId), newAccount);

        return ApiResponse.success("Update account success");
    }

    @PostMapping("/update/password")
    public ApiResponse updatePassword(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String credentialId = data.get("credentialId");
        String newPassword = data.get("newPassword");

        int encryptionId = credentialService.updatePassword(Integer.parseInt(userId), Integer.parseInt(credentialId), newPassword);

        return ApiResponse.success(encryptionId);
    }

    @PostMapping("/update/valid")
    public ApiResponse updateValid(@RequestBody Map<String, String> data) {
        int credentialId = Integer.parseInt(data.get("credentialId"));
        int valid = Integer.parseInt(data.get("valid"));
        credentialService.updateValid(credentialId, valid == 1);
        return ApiResponse.success("Update valid success");
    }
}
