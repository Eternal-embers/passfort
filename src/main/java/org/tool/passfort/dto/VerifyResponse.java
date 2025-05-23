package org.tool.passfort.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifyResponse {
    private String code; // 6位验证码
    private String codeKey;  // redis key
}
