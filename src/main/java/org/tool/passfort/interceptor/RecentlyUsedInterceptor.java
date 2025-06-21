package org.tool.passfort.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.tool.passfort.util.redis.RedisUtil;

@Component
public class RecentlyUsedInterceptor implements HandlerInterceptor {
    private final RedisUtil redisUtil;
    private static final String ACCESS_KEY_PREFIX = "credential_access";
    private static final String RECENTLY_USED_KEY_PREFIX = "credential_recently_used";

    @Autowired
    public RecentlyUsedInterceptor(RedisUtil redisUtil) {
        this.redisUtil = redisUtil;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String userId = (String) request.getAttribute("userId");
        String credentialId = (String) request.getAttribute("credentialId");

        if(userId != null && credentialId != null) {
            updateRecentlyUsed(userId, credentialId);
        }

        return true;
    }

    private void updateRecentlyUsed(String userId, String credentialId) {
        String accessKey = ACCESS_KEY_PREFIX + ":" + userId;
        String recentlyUsedKey = RECENTLY_USED_KEY_PREFIX + ":" + userId;

        Long length = redisUtil.lPush(accessKey, credentialId);
        redisUtil.zIncrementScore(recentlyUsedKey, credentialId, 1);  // 将最近使用的凭证数量加1

        if(length > 100) {  // 如果访问记录超过100条，则删除最早的一条
            String removedCredentialId = (String) redisUtil.rPop(accessKey);
            redisUtil.zIncrementScore(recentlyUsedKey, removedCredentialId, -1); // 将最近使用的凭证数量减1
        }
    }
}
