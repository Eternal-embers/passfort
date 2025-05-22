package org.tool.passfort.exception;

public class PasswordInvalidException extends Exception{
    private int failedLoginAttempts;
    public PasswordInvalidException(String email, int failedLoginAttempts) {
        super("Password invalid for email: " + email + ". Failed login attempts: " + failedLoginAttempts + ".");
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }
}
