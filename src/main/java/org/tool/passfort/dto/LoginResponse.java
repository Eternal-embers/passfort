package org.tool.passfort.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    private Integer userId;
    private String accessToken; //访问token
    private String refreshTokenKey; //刷新token的redis key
    private String refreshToken; //刷新token
    private Long accessTokenExpiresIn; // 访问Token有效期（秒）
    private Long refreshTokenExpiresIn; // 刷新Token有效期（秒）
}
