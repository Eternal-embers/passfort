package org.tool.passfort.exception;

public class PasswordHashingException extends Exception {

    public PasswordHashingException(String email, Exception cause) {
        super("Failed to hash password for email: " + email, cause);
    }
}
