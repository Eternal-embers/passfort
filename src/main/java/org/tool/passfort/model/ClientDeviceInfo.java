package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClientDeviceInfo {
    private String ipAddress; // 客户端 IP 地址
    private String deviceType; // 设备类型（如手机、平板、电脑等）
    private String osName; // 操作系统名称
    private String osVersion; // 操作系统版本
    private String browserName; // 浏览器名称
    private String browserVersion; // 浏览器版本
}