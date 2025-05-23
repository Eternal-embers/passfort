package org.tool.passfort.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    /**
     * 自定义 RedisTemplate，用于支持复杂对象的存储和序列化。
     * 默认的 RedisTemplate 使用的是 JdkSerializationRedisSerializer，它对存储的键值对进行了序列化，
     * 导致存储在 Redis 中的数据难以直接查看。通过自定义 RedisTemplate，可以使用更友好的序列化方式。
     *
     * @param factory Redis连接工厂
     * @return 自定义的 RedisTemplate
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);

        // 设置键（Key）的序列化方式
        template.setKeySerializer(new StringRedisSerializer());
        // 设置值（Value）的序列化方式
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        // 设置Hash类型键的序列化方式
        template.setHashKeySerializer(new StringRedisSerializer());
        // 设置Hash类型值的序列化方式
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());

        // 设置其他序列化方式（可选）
        template.setConnectionFactory(factory);
        template.afterPropertiesSet(); // 初始化 RedisTemplate
        return template;
    }

    /**
     * 提供一个默认的 StringRedisTemplate，用于操作字符串类型的键值对。
     * StringRedisTemplate 是 RedisTemplate 的一个子类，专门用于处理字符串类型的键值对。
     * 它默认使用 StringRedisSerializer 对键和值进行序列化和反序列化。
     *
     * @param factory Redis连接工厂
     * @return 默认的 StringRedisTemplate
     */
    @Bean
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory factory) {
        return new StringRedisTemplate(factory);
    }
}
