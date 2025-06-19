package org.tool.passfort.limiter.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tool.passfort.limiter.RateLimiter;
import org.tool.passfort.util.redis.RedisUtil;

import java.util.concurrent.TimeUnit;

@Component
public class RedisRateLimiter implements RateLimiter {
    private final RedisUtil redisUtil;
    private final int maxRequestsPerMinute = 30;// 每分钟最大请求次数

    @Autowired
    public RedisRateLimiter(RedisUtil redisUtil) {
        this.redisUtil = redisUtil;
    }

    @Override
    public boolean allowRequest(String requestUri, String clientIp) {
        // 生成唯一的key，格式为"IP:URI"
        String key = clientIp + ":" + requestUri;

        // 增加当前请求的次数
        Long currentRequests = redisUtil.increment(key, 1);

        // 如果是第一次访问，设置过期时间为 1 分钟
        if(currentRequests == 1) {
            redisUtil.expire(key, 1, TimeUnit.MINUTES);
        }

        // 检查是否超过限制
        return currentRequests <= maxRequestsPerMinute;
    }
}
