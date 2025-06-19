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

    // =============================数值操作================================

    /**
     * 增加数值
     * @param key 键, 如果指定的 key 不存在，Redis 会自动创建该 key，并将其初始值设置为 0
     * @param delta 增加的值（必须大于0）
     * @return 增加后的值
     */
    public Long increment(String key, long delta) {
        if (delta < 0) {
            throw new RuntimeException("Delta must be greater than 0");
        }
        return redisTemplate.opsForValue().increment(key, delta);
    }

    /**
     * 减少数值
     * @param key 键, 如果指定的 key 不存在，Redis 会自动创建该 key，并将其初始值设置为 0
     * @param delta 减少的值（必须0大于）
     * @return 减少后的值
     */
    public Long decrement(String key, long delta) {
        if (delta < 0) {
            throw new RuntimeException("Delta must be greater than 0");
        }
        return redisTemplate.opsForValue().decrement(key, delta);
    }

    /**
     * 设置数值（使用 RedisTemplate）
     * @param key 键
     * @param value 值
     */
    public void setLong(String key, Long value) {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 设置数值并设置过期时间（使用 RedisTemplate）
     * @param key 键
     * @param value 值
     * @param timeout 过期时间（秒）
     */
    public void setLong(String key, Long value, long timeout, TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 获取数值（使用 RedisTemplate）
     * @param key 键
     * @return 值
     */
    public Long getLong(String key) {
        return (Long) redisTemplate.opsForValue().get(key);
    }

    // =============================通用操作================================

    /**
     * 发送 PING 命令，检查 Redis 连接
     * @return 返回 PONG 表示连接成功，其他值表示连接失败
     */
    public String ping() {
        return stringRedisTemplate.getConnectionFactory().getConnection().ping();
    }

    /**
     * 设置键的过期时间
     *
     * @param key      键
     * @param timeout  过期时间
     * @param timeUnit 时间单位
     */
    public void expire(String key, long timeout, TimeUnit timeUnit) {
        redisTemplate.expire(key, timeout, timeUnit);
    }

    /**
     * 删除键
     * @param key 键
     */
    public void delete(String key) {
        redisTemplate.delete(key);
    }

    /**
     * 判断键是否存在
     *
     * @param key 键
     * @return 是否存在
     */
    public Boolean hasKey(String key) {
        return redisTemplate.hasKey(key);
    }

    /**
     * 获取键的剩余过期时间
     *
     * @param key 键
     * @return 剩余时间（秒），如果键不存在返回 -1, 如果键没有设置过期时间返回 -2
     */
    public Long getExpire(String key) {
        return redisTemplate.getExpire(key, TimeUnit.SECONDS);
    }

    /**
     * 判断键是否过期
     * @param key 键
     */
    public boolean isExpire(String key) {
        return redisTemplate.hasKey(key) && redisTemplate.getExpire(key, TimeUnit.SECONDS) <= 0;
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
