package org.tool.passfort.exception;

public class PasswordRepeatException extends Exception{
    public PasswordRepeatException(String email) {
        super("Password repeat for email: " + email);
    }
}
