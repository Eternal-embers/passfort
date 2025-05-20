package org.tool.passfort.exception;

public class PasswordInvalidException extends Exception{
    public PasswordInvalidException(String email) {
        super("Password invalid for email: " + email);
    }
}
