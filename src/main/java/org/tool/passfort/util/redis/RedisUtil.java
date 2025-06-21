package org.tool.passfort.util.redis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Component
public class RedisUtil<T> {
    private final RedisTemplate<String, T> redisTemplate;
    private final LettuceConnectionFactory lettuceConnectionFactory;

    @Autowired
    public RedisUtil(RedisTemplate<String, T> redisTemplate, LettuceConnectionFactory lettuceConnectionFactory){
        this.redisTemplate = redisTemplate;
        this.lettuceConnectionFactory = lettuceConnectionFactory;
    }

    // =============================键值对操作================================

    /**
     * 设置键值对
     *
     * @param key   键
     * @param value 值
     */
    public void set(String key, T value) {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 设置键值对，并设置过期时间
     *
     * @param key      键
     * @param value    值
     * @param timeout  过期时间
     * @param timeUnit 时间单位
     */
    public void set(String key, T value, long timeout, TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 获取键值对
     *
     * @param key 键
     * @return 值
     */
    public T get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 删除键
     * @param key 键
     */
    public void delete(String key) {
        redisTemplate.delete(key);
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

    // =============================数值操作================================

    /**
     * 增加数值
     * @param key 键, 如果指定的 key 不存在，Redis 会自动创建该 key，并将其初始值设置为 0
     * @param delta 增加的值
     * @return 增加 delta 后的值
     */
    public Long increment(String key, long delta) {
        return redisTemplate.opsForValue().increment(key, delta);
    }


    // ================================ List操作 ================================

    /**
     * 向列表头部插入元素
     * @param key 键
     * @param value 值
     * @return 插入后列表的长度
     */
    public Long lPush(String key, T value) {
        return redisTemplate.opsForList().leftPush(key, value);
    }

    /**
     * 向列表头部批量插入元素
     * @param key 键
     * @param values 值列表
     * @return 插入后列表的长度
     */
    public Long lPushAll(String key, Collection<T> values) {
        return redisTemplate.opsForList().leftPushAll(key, values);
    }

    /**
     * 向列表尾部插入元素
     * @param key 键
     * @param value 值
     * @return 插入后列表的长度
     */
    public Long rPush(String key, T value) {
        return redisTemplate.opsForList().rightPush(key, value);
    }

    /**
     * 向列表尾部批量插入元素
     * @param key 键
     * @param values 值列表
     * @return 插入后列表的长度
     */
    public Long rPushAll(String key, Collection<T> values) {
        return redisTemplate.opsForList().rightPushAll(key, values);
    }

    /**
     * 从列表头部移除并返回元素
     * @param key 键
     * @return 被移除的元素
     */
    public T lPop(String key) {
        return redisTemplate.opsForList().leftPop(key);
    }

    /**
     * 从列表尾部移除并返回元素
     * @param key 键
     * @return 被移除的元素
     */
    public T rPop(String key) {
        return redisTemplate.opsForList().rightPop(key);
    }

    /**
     * 获取列表中指定范围的元素
     * @param key 键
     * @param start 开始索引
     * @param end 结束索引
     * @return 指定范围内的元素列表
     */
    public List<T> lRange(String key, long start, long end) {
        return redisTemplate.opsForList().range(key, start, end);
    }

    /**
     * 获取列表的长度
     * @param key 键
     * @return 列表的长度
     */
    public Long lSize(String key) {
        return redisTemplate.opsForList().size(key);
    }

    /**
     * 设置列表中指定索引位置的元素
     * @param key 键
     * @param index 索引
     * @param value 新值
     */
    public void lSet(String key, long index, T value) {
        redisTemplate.opsForList().set(key, index, value);
    }

    /**
     * 移除列表中指定值的元素
     * @param key 键
     * @param count 移除的数量（count > 0: 移除头部的 count 个匹配元素；count < 0: 移除尾部的 count 个匹配元素；count = 0: 移除所有匹配元素）
     * @param value 要移除的值
     * @return 被移除的元素数量
     */
    public Long lRemove(String key, long count, String value) {
        return redisTemplate.opsForList().remove(key, count, value);
    }

    // -----------------------无序集合-----------------------

    /**
     * 向集合中添加元素
     * @param key 键
     * @param values 值
     * @return 添加成功的元素数量
     */
    public Long sAdd(String key, T... values) {
        return redisTemplate.opsForSet().add(key, values);
    }

    /**
     * 从集合中移除元素
     * @param key 键
     * @param values 值
     * @return 被移除的元素数量
     */
    public Long sRemove(String key, T... values) {
        return redisTemplate.opsForSet().remove(key, values);
    }

    /**
     * 判断元素是否在集合中
     * @param key 键
     * @param value 值
     * @return 是否存在
     */
    public Boolean sIsMember(String key, String value) {
        return redisTemplate.opsForSet().isMember(key, value);
    }

    /**
     * 获取集合中的所有元素
     * @param key 键
     * @return 集合中的所有元素
     */
    public Set<T> sMembers(String key) {
        return redisTemplate.opsForSet().members(key);
    }

    /**
     * 获取集合的大小
     * @param key 键
     * @return 集合的大小
     */
    public Long sSize(String key) {
        return redisTemplate.opsForSet().size(key);
    }

    /**
     * 随机移除并返回集合中的一个元素
     * @param key 键
     * @return 被移除的元素
     */
    public T sPop(String key) {
        return redisTemplate.opsForSet().pop(key);
    }

    /**
     * 随机返回集合中的一个元素
     * @param key 键
     * @return 随机元素
     */
    public T sRandomMember(String key) {
        return redisTemplate.opsForSet().randomMember(key);
    }

    /**
     * 返回集合中指定数量的随机元素
     * @param key 键
     * @param count 数量
     * @return 随机元素列表
     */
    public List<T> sRandomMembers(String key, long count) {
        return redisTemplate.opsForSet().randomMembers(key, count);
    }

    /**
     * 计算多个集合的交集
     * @param keys 键列表
     * @return 交集结果
     */
    public Set<T> sIntersect(String... keys) {
        return redisTemplate.opsForSet().intersect(List.of(keys));
    }

    /**
     * 计算多个集合的并集
     * @param keys 键列表
     * @return 并集结果
     */
    public Set<T> sUnion(String... keys) {
        return redisTemplate.opsForSet().union(List.of(keys));
    }

    /**
     * 计算多个集合的差集
     * @param key 主键
     * @param otherKeys 其他键
     * @return 差集结果
     */
    public Set<T> sDifference(String key, String... otherKeys) {
        return redisTemplate.opsForSet().difference(key, List.of(otherKeys));
    }

    // =============================有序集合================================

    /**
     * 添加成员到有序集合
     * @param key 键
     * @param member 成员
     * @param score 分数
     * @return 是否添加成功
     */
    public Boolean zAdd(String key, T member, double score) {
        return redisTemplate.opsForZSet().add(key, member, score);
    }

    /**
     * 批量添加成员到有序集合
     * @param key 键
     * @param typedTuples 成员及其分数
     * @return 添加成功的成员数量
     */
    public Long zAdd(String key, Set<ZSetOperations.TypedTuple<T>> typedTuples) {
        return redisTemplate.opsForZSet().add(key, typedTuples);
    }

    /**
     * 从有序集合中移除成员
     * @param key 键
     * @param members 成员
     * @return 被移除的成员数量
     */
    public Long zRemove(String key, T... members) {
        return redisTemplate.opsForZSet().remove(key, members);
    }

    /**
     * 获取成员的分数
     * @param key 键
     * @param member 成员
     * @return 成员的分数
     */
    public Double zScore(String key, T member) {
        return redisTemplate.opsForZSet().score(key, member);
    }

    /**
     * 增加成员的分数
     * @param key 键
     * @param member 成员
     * @param delta 增加的分数
     * @return 增加后的分数
     */
    public Double zIncrementScore(String key, T member, double delta) {
        return redisTemplate.opsForZSet().incrementScore(key, member, delta);
    }

    /**
     * 获取有序集合中指定范围的成员（按分数排序）
     * @param key 键
     * @param start 开始索引
     * @param end 结束索引
     * @return 指定范围内的成员列表
     */
    public Set<T> zRange(String key, long start, long end) {
        return redisTemplate.opsForZSet().range(key, start, end);
    }

    /**
     * 获取有序集合中指定范围的成员（按分数倒序排序）
     * @param key 键
     * @param start 开始索引
     * @param end 结束索引
     * @return 指定范围内的成员列表
     */
    public Set<T> zReverseRange(String key, long start, long end) {
        return redisTemplate.opsForZSet().reverseRange(key, start, end);
    }

    /**
     * 获取有序集合中指定分数范围的成员
     * @param key 键
     * @param min 最小分数
     * @param max 最大分数
     * @return 指定分数范围内的成员列表
     */
    public Set<T> zRangeByScore(String key, double min, double max) {
        return redisTemplate.opsForZSet().rangeByScore(key, min, max);
    }

    /**
     * 获取有序集合中指定分数范围的成员（按分数递增排序，带分页）
     * @param key 键
     * @param min 最小分数
     * @param max 最大分数
     * @param offset 偏移量, 用于指定返回结果的起始位置
     * @param count 数量, 返回指定数量的成员
     * @return 指定分数范围内的成员列表
     */
    public Set<T> zRangeByScore(String key, double min, double max, long offset, long count) {
        return redisTemplate.opsForZSet().rangeByScore(key, min, max, offset, count);
    }

    /**
     * 获取有序集合中指定分数范围的成员（按分数递减排序）
     * @param key 键
     * @param min 最小分数
     * @param max 最大分数
     * @param offset 偏移量, 用于指定返回结果的起始位置
     * @param count 数量, 返回指定数量的成员
     * @return 指定分数范围内的成员列表
     */
    public Set<T> zReverseRangeByScore(String key, double min, double max, long offset, long count) {
        return redisTemplate.opsForZSet().reverseRangeByScore(key, min, max, offset, count);
    }

    /**
     * 获取有序集合的大小
     * @param key 键
     * @return 有序集合的大小
     */
    public Long zSetSize(String key) {
        return redisTemplate.opsForZSet().size(key);
    }

    /**
     * 获取有序集合中成员的排名（按分数排序）
     * @param key 键
     * @param member 成员
     * @return 成员的排名
     */
    public Long zRank(String key, T member) {
        return redisTemplate.opsForZSet().rank(key, member);
    }

    /**
     * 获取有序集合中成员的排名（按分数倒序排序）
     * @param key 键
     * @param member 成员
     * @return 成员的排名
     */
    public Long zReverseRank(String key, T member) {
        return redisTemplate.opsForZSet().reverseRank(key, member);
    }

    /**
     * 删除有序集合中指定分数范围的成员
     * @param key 键
     * @param min 最小分数
     * @param max 最大分数
     * @return 被移除的成员数量
     */
    public Long zRemoveRangeByScore(String key, double min, double max) {
        return redisTemplate.opsForZSet().removeRangeByScore(key, min, max);
    }

    /**
     * 删除有序集合中指定范围的成员
     * @param key 键
     * @param start 开始索引
     * @param end 结束索引
     * @return 被移除的成员数量
     */
    public Long zRemoveRange(String key, long start, long end) {
        return redisTemplate.opsForZSet().removeRange(key, start, end);
    }

    /**
     * 获取有序集合中成员的分数区间（按分数排序）
     * @param key 键
     * @param start 开始索引
     * @param end 结束索引
     * @return 成员及其分数
     */
    public Set<ZSetOperations.TypedTuple<T>> zRangeWithScores(String key, long start, long end) {
        return redisTemplate.opsForZSet().rangeWithScores(key, start, end);
    }

    /**
     * 获取有序集合中成员的分数区间（按分数倒序排序）
     * @param key 键
     * @param start 开始索引
     * @param end 结束索引
     * @return 成员及其分数
     */
    public Set<ZSetOperations.TypedTuple<T>> zReverseRangeWithScores(String key, long start, long end) {
        return redisTemplate.opsForZSet().reverseRangeWithScores(key, start, end);
    }

    /**
     * 获取有序集合中指定分数范围的成员及其分数
     * @param key 键
     * @param min 最小分数
     * @param max 最大分数
     * @return 成员及其分数
     */
    public Set<ZSetOperations.TypedTuple<T>> zRangeByScoreWithScores(String key, double min, double max) {
        return redisTemplate.opsForZSet().rangeByScoreWithScores(key, min, max);
    }

    /**
     * 获取有序集合中指定分数范围的成员及其分数（带分页）
     * @param key 键
     * @param min 最小分数
     * @param max 最大分数
     * @param offset 偏移量, 用于指定返回结果的起始位置
     * @param count 数量
     * @return 成员及其分数
     */

    public Set<ZSetOperations.TypedTuple<T>> zRangeByScoreWithScores(String key, double min, double max, long offset, long count) {
        return redisTemplate.opsForZSet().rangeByScoreWithScores(key, min, max, offset, count);
    }

    // =============================自定义================================

    /**
     * 发送 PING 命令，检查 Redis 连接
     * @return 返回 PONG 表示连接成功，其他值表示连接失败
     */
    public String ping() {
        return Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection().ping();
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
            return version;
        }
    }
}
