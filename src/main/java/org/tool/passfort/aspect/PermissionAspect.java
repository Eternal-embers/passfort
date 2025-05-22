package org.tool.passfort.aspect;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tool.passfort.exception.MissingRequestContextException;
import org.tool.passfort.mapper.UserMapper;
import org.tool.passfort.util.jwt.JwtUtil;

@Aspect
@Component
public class PermissionAspect {
    private static final Logger logger = LoggerFactory.getLogger(PermissionAspect.class);
    private JwtUtil jwtUtil;
    private UserMapper userMapper;

    @Autowired
    public PermissionAspect(JwtUtil jwtUtil, UserMapper userMapper){
        this.jwtUtil = jwtUtil;
        this.userMapper = userMapper;
    }

    // 定义切入点，拦截所有被 @AuthRequired 注解标注的方法和被注解的类中的所有方法
    @Pointcut("@annotation(org.tool.passfort.annotation.AuthRequired) || @within(org.tool.passfort.annotation.AuthRequired)")
    public void authCheck() {}

    @Before("authCheck()")
    public void checkAuth(JoinPoint joinPoint) throws MissingRequestContextException {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if(attributes == null) {
            logger.error("No active request context found. HttpServletRequest is null.");
            throw new MissingRequestContextException();
        }

        HttpServletRequest request = attributes.getRequest();
        String requestPath = request.getRequestURI();



    }
}
