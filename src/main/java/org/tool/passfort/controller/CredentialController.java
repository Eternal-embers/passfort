package org.tool.passfort.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.model.Credential;
import org.tool.passfort.service.CredentialService;
import org.tool.passfort.util.encrypt.AesUtil;
import org.tool.passfort.util.encrypt.ShuffleEncryption;

import java.util.Map;

@RestController
@RequestMapping("/api/credential")
public class CredentialController {
    private final CredentialService credentialService;
    private final AesUtil aesUtil;
    private final static int CHUNK_SIZE = 8;
    private final static int[] SHUFFLE_ORDER = {7, 2, 5, 0, 3, 6, 1, 4};

    @Autowired
    public CredentialController(CredentialService credentialService, AesUtil aesUtil) {
        this.credentialService = credentialService;
        this.aesUtil = aesUtil;
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

    @PostMapping("/view")
    public ApiResponse viewPassword(HttpServletRequest request, @RequestBody Map<String, String> data) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String encryptionId = data.get("encryptionId");
        String password = credentialService.getPassword(Integer.valueOf(userId), Integer.valueOf(encryptionId));

        // 对密码进行混淆加密
        byte[] encryptedPassword = aesUtil.encrypt(password);//iv, key, encryptedPassword的组合, 64字节
        byte[] shuffledEncryptedPassword = ShuffleEncryption.shuffleEncrypt(encryptedPassword, CHUNK_SIZE, SHUFFLE_ORDER);

        return ApiResponse.success(shuffledEncryptedPassword);
    }
}
