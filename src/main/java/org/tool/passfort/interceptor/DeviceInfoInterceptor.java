package org.tool.passfort.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.tool.passfort.model.ClientDeviceInfo;
import org.tool.passfort.util.http.UserAgentUtil;

@Component
public class DeviceInfoInterceptor implements HandlerInterceptor {
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // 获取客户端 IP 地址
        String ipAddress = getRealIp(request);

        // 获取 User-Agent
        String userAgent = request.getHeader("User-Agent");

        // 解析 User-Agent 获取设备信息
        ClientDeviceInfo clientDeviceInfo = UserAgentUtil.parseUserAgent(userAgent);
        clientDeviceInfo.setIpAddress(ipAddress);

        // 将设备信息存储到请求属性中，方便后续调用
        request.setAttribute("clientDeviceInfo", clientDeviceInfo);

        return true;
    }

    /**
     * 获取客户端的真实 IP 地址
     * @param request HTTP 请求
     * @return 客户端的真实 IP 地址
     */
    private String getRealIp(HttpServletRequest request) {
        /*
          优先从 X-Forwarded-For 请求头中获取客户端的真实 IP 地址
          X-Forwarded-For 是一个标准的 HTTP 请求头，通常由代理服务器（如 Nginx）设置。它用于记录原始客户端的 IP 地址，即使请求经过了代理服务器。
         */
        String ipAddress = request.getHeader("X-Forwarded-For");

        /*
          X-Real-IP 是另一个常用的 HTTP 请求头，通常由 Nginx 设置。它用于记录原始客户端的 IP 地址。
         */
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            // 如果 X-Forwarded-For 为空或未知，则尝试从 X-Real-IP 请求头中获取
            ipAddress = request.getHeader("X-Real-IP");
        }

        /*
          当请求直接到达服务器（没有经过代理）时，request.getRemoteAddr() 返回的是客户端的真实 IP 地址。
        */
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            // 如果 X-Real-IP 也为空或未知，则使用 request.getRemoteAddr()
            ipAddress = request.getRemoteAddr();
        }

        /*
            如果 X-Forwarded-For 的值包含多个 IP 地址（以逗号分隔），第一个 IP 地址通常是客户端的真实 IP 地址。后续的 IP 地址通常是代理服务器的 IP 地址。
         */
        if (ipAddress != null && ipAddress.contains(",")) {
            // 如果 X-Forwarded-For 中包含多个 IP 地址（以逗号分隔），则取第一个 IP 地址
            ipAddress = ipAddress.split(",")[0].trim();
        }

        return ipAddress;
    }
}
