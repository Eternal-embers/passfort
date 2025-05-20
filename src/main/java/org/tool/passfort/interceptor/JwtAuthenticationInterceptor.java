package org.tool.passfort.interceptor;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.tool.passfort.util.jwt.JwtUtil;

@Component
public class JwtAuthenticationInterceptor implements HandlerInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationInterceptor.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取请求头中的JWT
        String token = request.getHeader("Authorization");

        if (token == null || !token.startsWith("Bearer ")) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or missing token");
            return false;
        }

        token = token.substring(7); // 去掉"Bearer "前缀

        try {
            jwtUtil.verifyToken(token);
        } catch (JWTVerificationException e) {
            // 提供更详细的错误信息
            response.sendError(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            return false;
        } catch (Exception e) {
            // 捕获其他异常
            response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Unexpected error occurred");
            return false;
        }

        // 如果JWT校验通过，继续处理请求
        return true;
    }
}
