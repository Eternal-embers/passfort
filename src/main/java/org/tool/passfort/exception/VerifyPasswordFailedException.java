package org.tool.passfort.exception;

public class VerifyPasswordFailedException extends Exception{
    public VerifyPasswordFailedException(String email) {
        super("Failed to verify password for email: " + email);
    }
}
