package org.tool.passfort.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.tool.passfort.exception.*;
import org.tool.passfort.dto.ApiResponse;

import org.springframework.http.HttpStatus;

@ControllerAdvice
@ResponseBody
@SuppressWarnings("rawtypes") // 消除ApiResponse的原始类型警告
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(DatabaseOperationException.class)
    public ApiResponse handleDatabaseOperationException(DatabaseOperationException e) {
        return ApiResponse.failure(500, e.getMessage());
    }

    @ExceptionHandler(PasswordHashingException.class)
    public ApiResponse handlePasswordHashingException(PasswordHashingException e) {
        return ApiResponse.failure(500, e.getMessage());
    }

    @ExceptionHandler(EmailAlreadyRegisteredException.class)
    public ApiResponse handleEmailAlreadyRegisteredException(EmailAlreadyRegisteredException e) {
        return ApiResponse.failure(400, e.getMessage(), "email_already_registered");
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ApiResponse handleUserNotFoundException(UserNotFoundException e) {
        return ApiResponse.failure(404, e.getMessage(), "user_not_found");
    }

    @ExceptionHandler(AccountLockedException.class)
    public ApiResponse handleAccountLockedException(AccountLockedException e) {
        return ApiResponse.failure(403, e.getMessage(), "account_locked");
    }

    @ExceptionHandler(VerifyPasswordFailedException.class)
    public ApiResponse handleVerifyPasswordFailedException(VerifyPasswordFailedException e) {
        return ApiResponse.failure(401, e.getMessage());
    }

    @ExceptionHandler(AccountNotActiveException.class)
    public ApiResponse handleAccountNotActiveException(AccountNotActiveException e) {
        return ApiResponse.failure(403, e.getMessage());
    }

    @ExceptionHandler(PasswordInvalidException.class)
    public ApiResponse  handlePasswordInvalidException(PasswordInvalidException e) {
        return ApiResponse.failure(401, e.getMessage(), "password_error");
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ApiResponse handleUnauthorizedException(UnauthorizedException e) {
        return ApiResponse.failure(403, e.getMessage());
    }

    @ExceptionHandler(PasswordRepeatException.class)
    public ApiResponse handlePasswordRepeatException(PasswordRepeatException e) {
        return ApiResponse.failure(400, e.getMessage());
    }

    @ExceptionHandler(AuthenticationExpiredException.class)
    public ApiResponse handleAuthenticationExpiredException(AuthenticationExpiredException e) {
        return ApiResponse.failure(401, e.getMessage(), "Expired");
    }

    @ExceptionHandler(VerificationCodeErrorException.class)
    public ApiResponse handleVerificationCodeErrorException(VerificationCodeErrorException e) {
        return ApiResponse.failure(400, e.getMessage(), "code_error");
    }

    @ExceptionHandler(VerificationCodeExpireException.class)
    public ApiResponse handleVerificationCodeExpireException(VerificationCodeExpireException e) {
        return ApiResponse.failure(400, e.getMessage(), "code_expire");
    }

    @ExceptionHandler(SecurityQuestionVerificationException.class)
    public ApiResponse handleSecurityQuestionVerificationException(SecurityQuestionVerificationException e) {
        return ApiResponse.failure(400, e.getMessage(), e.getErrorQuestionIndex()); // 返回错误问题的索引
    }

    @ExceptionHandler(PersonalInfoVerificationException.class)
    public ApiResponse handlePersonalInfoVerificationException(PersonalInfoVerificationException e) {
        return ApiResponse.failure(400, e.getMessage(), e.getErrorParam()); // 返回错误字段
    }

    @ExceptionHandler(OtherInfoVerificationException.class)
    public ApiResponse handleOtherInfoVerificationException(OtherInfoVerificationException e) {
        return ApiResponse.failure(400, e.getMessage(), e.getErrorParam()); // 返回错误字段
    }

    @ExceptionHandler(PasswordVerificationException.class)
    public ApiResponse handlePasswordVerificationException(PasswordVerificationException e) {
        return ApiResponse.failure(400, e.getMessage(), e.getFailedVerificationAttempts());
    }

    @ExceptionHandler(LoginRevocationException.class)
    public ApiResponse handleLoginRevocationException(LoginRevocationException e) {
        return ApiResponse.failure(401, e.getMessage(), "login_revocation");
    }

    // 捕获所有未明确处理的异常
    @ExceptionHandler(Exception.class)
    public ApiResponse handleException(Exception e) {
        // 打印异常类型、异常消息和堆栈跟踪的首行
        logger.error("Unhandled exception: {} - {} - {}", e.getClass().getName(), e.getMessage(), e.getStackTrace()[0].toString());
        return ApiResponse.failure(500, "Unexpected error occurred");
    }
}