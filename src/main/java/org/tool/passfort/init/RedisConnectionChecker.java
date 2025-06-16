package org.tool.passfort.init;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.tool.passfort.util.redis.RedisUtil;

@Component
@Order(3)
public class RedisConnectionChecker implements ApplicationRunner {
    private static final Logger logger = LoggerFactory.getLogger(RedisConnectionChecker.class);
    private final RedisUtil redisUtil;

    @Autowired
    public RedisConnectionChecker(RedisUtil redisUtil) {
        this.redisUtil = redisUtil;
    }

    @Override
    public void run(ApplicationArguments args) {
        // 使用 Redis 的 PING 命令检查连接
        try {
            String response = redisUtil.ping();
            if ("PONG".equalsIgnoreCase(response)) {
                logger.info("Connected to Redis successfully.");
            } else {
                throw new RuntimeException("Redis connection test failed: Unexpected response from PING command.");
            }
        } catch (Exception e) {
            logger.error("Failed to connect to Redis: {}", e.getMessage());
        }
    }
}
