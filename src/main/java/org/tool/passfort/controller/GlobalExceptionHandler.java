package org.tool.passfort.controller;

import org.springframework.web.bind.annotation.*;
import org.tool.passfort.exception.*;
import org.tool.passfort.model.ApiResponse;

import org.springframework.http.HttpStatus;

@ControllerAdvice
@ResponseBody
public class GlobalExceptionHandler {
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
        return ApiResponse.failure(403, e.getMessage());
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
        return ApiResponse.failure(401, e.getMessage());
    }

    // 捕获所有未明确处理的异常
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse handleException(Exception e) {
        return ApiResponse.failure(500, "Internal Server Error: " + e.getMessage());
    }
}
