package org.tool.passfort.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.tool.passfort.limiter.RateLimiter;
import org.tool.passfort.model.ClientDeviceInfo;

import java.io.IOException;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(RateLimitInterceptor.class);
    private final RateLimiter rateLimiter;

    @Autowired
    public RateLimitInterceptor(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        ClientDeviceInfo clientDeviceInfo = (ClientDeviceInfo) request.getAttribute("clientDeviceInfo");
        String clientIp = clientDeviceInfo.getIpAddress();

        String requestUri = request.getRequestURI();

        if (!rateLimiter.allowRequest(requestUri, clientIp)) { // allowRequest 会在 Redis 中记录请求次数，并判断是否超过限制
            logger.warn("Rate limit exceeded for IP address: {}", clientIp);
            response.sendError(429, "Rate limit exceeded. Please try again later.");
            return false;
        }

        return true;
    }
}
