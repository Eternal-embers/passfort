package org.tool.passfort.limiter.impl;

import org.springframework.stereotype.Component;
import org.tool.passfort.limiter.RateLimiter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class SimpleRateLimiter implements RateLimiter {
    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> requestTimestamps = new ConcurrentHashMap<>();
    private final int maxRequestsPerMinute = 10; // 每分钟最大请求次数
    private final long interval = 60 * 1000; // 1分钟的毫秒数

    @Override
    public boolean allowRequest(String requestUri, String clientIp) {
        // 生成唯一的key，格式为"IP:URI"
        String key = clientIp + ":" + requestUri;

        // 获取当前时间
        long now = System.currentTimeMillis();

        // 检查是否需要重置计数器
        if (requestTimestamps.containsKey(key) && now - requestTimestamps.get(key) > interval) {
            // 如果时间超过1分钟，重置计数器
            requestCounts.put(key, new AtomicInteger(0));
            requestTimestamps.put(key, now);
        }

        // 如果是第一次访问，初始化计数器和时间戳
        requestCounts.putIfAbsent(key, new AtomicInteger(0));
        requestTimestamps.putIfAbsent(key, now);

        // 增加当前请求的次数
        int currentRequests = requestCounts.get(key).incrementAndGet();

        // 检查是否超过限制
        return currentRequests <= maxRequestsPerMinute;
    }
}
