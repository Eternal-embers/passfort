package org.tool.passfort.util.redis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Properties;
import java.util.concurrent.TimeUnit;

@Component
public class RedisUtil {
    private final StringRedisTemplate stringRedisTemplate;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LettuceConnectionFactory lettuceConnectionFactory;

    @Autowired
    public RedisUtil(StringRedisTemplate stringRedisTemplate, RedisTemplate<String, Object> redisTemplate, LettuceConnectionFactory lettuceConnectionFactory){
        this.stringRedisTemplate = stringRedisTemplate;
        this.redisTemplate = redisTemplate;
        this.lettuceConnectionFactory = lettuceConnectionFactory;
    }

    // =============================String操作================================

    /**
     * 设置字符串键值对
     *
     * @param key   键
     * @param value 值
     */
    public void setString(String key, String value) {
        stringRedisTemplate.opsForValue().set(key, value);
    }

    /**
     * 设置字符串键值对，并设置过期时间
     *
     * @param key      键
     * @param value    值
     * @param timeout  过期时间
     * @param timeUnit 时间单位
     */
    public void setString(String key, String value, long timeout, TimeUnit timeUnit) {
        stringRedisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 获取字符串键值对
     *
     * @param key 键
     * @return 值
     */
    public String getString(String key) {
        return stringRedisTemplate.opsForValue().get(key);
    }

    /**
     * 删除字符串键值对
     *
     * @param key 键
     */
    public void deleteString(String key) {
        stringRedisTemplate.delete(key);
    }

    // =============================Object操作================================

    /**
     * 设置对象键值对
     *
     * @param key   键
     * @param value 值
     */
    public void setObject(String key, Object value) {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 设置对象键值对，并设置过期时间
     *
     * @param key      键
     * @param value    值
     * @param timeout  过期时间
     * @param timeUnit 时间单位
     */
    public void setObject(String key, Object value, long timeout, TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 获取对象键值对
     *
     * @param key 键
     * @return 值
     */
    public Object getObject(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 删除对象键值对
     *
     * @param key 键
     */
    public void deleteObject(String key) {
        redisTemplate.delete(key);
    }

    // =============================通用操作================================

    /**
     * 设置键的过期时间
     *
     * @param key      键
     * @param timeout  过期时间
     * @param timeUnit 时间单位
     */
    public void expire(String key, long timeout, TimeUnit timeUnit) {
        stringRedisTemplate.expire(key, timeout, timeUnit);
    }

    /**
     * 判断键是否存在
     *
     * @param key 键
     * @return 是否存在
     */
    public Boolean hasKey(String key) {
        return stringRedisTemplate.hasKey(key);
    }

    /**
     * 获取键的剩余过期时间
     *
     * @param key 键
     * @return 剩余时间（秒），如果键不存在返回 -1, 如果键没有设置过期时间返回 -2
     */
    public Long getExpire(String key) {
        return stringRedisTemplate.getExpire(key, TimeUnit.SECONDS);
    }

    /**
     * 判断键是否过期
     * @param key 键
     */
    public boolean isExpire(String key) {
        return stringRedisTemplate.hasKey(key) && stringRedisTemplate.getExpire(key, TimeUnit.SECONDS) <= 0;
    }

    /**
     * 获取 Redis 版本
     *
     * @return Redis 版本
     */
    public String getVersion() {
        try (RedisConnection connection = lettuceConnectionFactory.getConnection()) {
            Properties info = connection.serverCommands().info("SERVER");
            if (info == null) return "Unknown";
            String version = info.getProperty("redis_version");
            if (version == null) return "Unknown";
            return "Version " + version;
        }
    }
}
