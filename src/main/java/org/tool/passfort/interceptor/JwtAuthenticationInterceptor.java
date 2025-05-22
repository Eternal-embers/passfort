package org.tool.passfort.interceptor;

import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.tool.passfort.dto.ApiResponse;
import org.tool.passfort.util.jwt.JwtUtil;

@Component
public class JwtAuthenticationInterceptor implements HandlerInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationInterceptor.class);
    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Autowired
    public JwtAuthenticationInterceptor(JwtUtil jwtUtil, ObjectMapper objectMapper) {
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
    }

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
            DecodedJWT decodedJWT = jwtUtil.verifyToken(token);
            String userId = decodedJWT.getSubject();
            String email = decodedJWT.getClaim("email").asString();
            String tokenType  = decodedJWT.getClaim("tokenType").asString();

            if (!tokenType.equals("access")) {
                response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid token type");
            }

            request.setAttribute("userId", userId);
            request.setAttribute("email", email);
        } catch (JWTVerificationException e) {
            String errorMessage = getString(e);
            ApiResponse<String> apiResponse = ApiResponse.failure(HttpStatus.UNAUTHORIZED.value(), errorMessage);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
            return false;
        } catch (Exception e) {
            // 捕获其他异常
            ApiResponse<String> apiResponse = ApiResponse.failure(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Unexpected error occurred: " + e.getMessage());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
            return false;
        }

        // 如果JWT校验通过，继续处理请求
        return true;
    }

    @NotNull
    private static String getString(JWTVerificationException e) {
        String errorMessage = "Invalid token: ";
        switch (e) {
            case TokenExpiredException tokenExpiredException ->
                    errorMessage += "Token has expired.";
            case SignatureVerificationException signatureVerificationException ->
                    errorMessage += "Token signature verification failed.";
            case AlgorithmMismatchException algorithmMismatchException ->
                    errorMessage += "Token algorithm mismatch.";
            case InvalidClaimException invalidClaimException ->
                    errorMessage += "Token claim is invalid.";
            case JWTDecodeException jwtDecodeException ->
                    errorMessage += "Token format is invalid.";
            default ->
                    errorMessage += "General JWT verification error.";
        }
        return errorMessage;
    }
}
