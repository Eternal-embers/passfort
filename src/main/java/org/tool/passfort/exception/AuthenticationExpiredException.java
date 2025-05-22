package org.tool.passfort.exception;

public class AuthenticationExpiredException extends Exception {
    public AuthenticationExpiredException(String message) {
        super(message);
    }
}
