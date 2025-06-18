package org.tool.passfort.exception;

public class PasswordVerificationException extends Exception{
    private final Integer failedVerificationAttempts; // 密码验证失败次数
    public PasswordVerificationException(String message, Integer failedVerificationAttempts) {
        super(message);
        this.failedVerificationAttempts = failedVerificationAttempts;
    }

    public Integer getFailedVerificationAttempts() {
        return failedVerificationAttempts;
    }
}
