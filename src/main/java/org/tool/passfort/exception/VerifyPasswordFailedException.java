package org.tool.passfort.exception;

public class VerifyPasswordFailedException extends Exception{
    public VerifyPasswordFailedException(String email) {
        super("an error occurred while verifying password for email: " + email);
    }
}
