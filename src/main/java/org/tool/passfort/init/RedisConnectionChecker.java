package org.tool.passfort.init;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.tool.passfort.util.redis.RedisUtil;

@Component
public class RedisConnectionChecker implements ApplicationRunner {
    private static final Logger logger = LoggerFactory.getLogger(RedisConnectionChecker.class);
    private final RedisUtil redisUtil;

    @Autowired
    public RedisConnectionChecker(RedisUtil redisUtil) {
        this.redisUtil = redisUtil;
    }

    @Override
    public void run(ApplicationArguments args) {
        // 检查 Redis 连接
        try {
            // 尝试写入一个测试键值对
            String testKey = "connectionTestKey";
            String testValue = "connectionTestValue";
            redisUtil.setString(testKey, testValue);

            // 检查是否能够读取该键值对
            String retrievedValue = redisUtil.getString(testKey);
            if (testValue.equals(retrievedValue)) {
                logger.info("Connected to Redis successfully.");
            } else {
                throw new RuntimeException("Redis connection test failed: Retrieved value does not match.");
            }

            // 删除测试键值对
            redisUtil.deleteString(testKey);
        } catch (Exception e) {
            logger.error("Failed to connect to Redis: {}", e.getMessage());
        }
    }
}
