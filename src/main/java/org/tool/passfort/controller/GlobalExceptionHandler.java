package org.tool.passfort.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.tool.passfort.exception.*;
import org.tool.passfort.dto.ApiResponse;

import org.springframework.http.HttpStatus;

@ControllerAdvice
@ResponseBody
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(DatabaseOperationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse handleDatabaseOperationException(DatabaseOperationException e) {
        return ApiResponse.failure(500, e.getMessage());
    }

    @ExceptionHandler(PasswordHashingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse handlePasswordHashingException(PasswordHashingException e) {
        return ApiResponse.failure(500, e.getMessage());
    }

    @ExceptionHandler(EmailAlreadyRegisteredException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse handleEmailAlreadyRegisteredException(EmailAlreadyRegisteredException e) {
        return ApiResponse.failure(400, e.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiResponse handleUserNotFoundException(UserNotFoundException e) {
        return ApiResponse.failure(404, e.getMessage());
    }

    @ExceptionHandler(AccountLockedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ApiResponse handleAccountLockedException(AccountLockedException e) {
        return ApiResponse.failure(403, e.getMessage(), e.lockoutUntil);
    }

    @ExceptionHandler(VerifyPasswordFailedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiResponse handleVerifyPasswordFailedException(VerifyPasswordFailedException e) {
        return ApiResponse.failure(401, e.getMessage());
    }

    @ExceptionHandler(AccountNotActiveException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ApiResponse handleAccountNotActiveException(AccountNotActiveException e) {
        return ApiResponse.failure(403, e.getMessage());
    }

    @ExceptionHandler(PasswordInvalidException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiResponse  handlePasswordInvalidException(PasswordInvalidException e) {
        return ApiResponse.failure(401, e.getMessage(), e.getFailedLoginAttempts());
    }

    @ExceptionHandler(UnauthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiResponse handleUnauthorizedException(UnauthorizedException e) {
        return ApiResponse.failure(403, e.getMessage());
    }

    @ExceptionHandler(PasswordRepeatException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse handlePasswordRepeatException(PasswordRepeatException e) {
        return ApiResponse.failure(400, e.getMessage());
    }

    @ExceptionHandler(AuthenticationExpiredException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiResponse handleAuthenticationExpiredException(AuthenticationExpiredException e) {
        return ApiResponse.failure(401, e.getMessage(), "Expired");
    }

    public ApiResponse handleVerificationCodeErrorException(VerificationCodeErrorException e) {
        return ApiResponse.failure(400, e.getMessage(), "VerificationCodeError");
    }

    // 捕获所有未明确处理的异常
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse handleException(Exception e) {
        // 打印异常类型、异常消息和堆栈跟踪的首行
        logger.error("Unhandled exception: {} - {} - {}", e.getClass().getName(), e.getMessage(), e.getStackTrace()[0].toString());
        return ApiResponse.failure(500, "Unexpected error occurred: " + e.getMessage());
    }
}