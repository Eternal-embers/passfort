package org.tool.passfort.limiter;

public interface RateLimiter {
    boolean allowRequest(String requestUri, String clientIp);
}
