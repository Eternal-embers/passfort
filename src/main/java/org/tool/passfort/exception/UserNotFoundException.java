package org.tool.passfort.exception;

public class UserNotFoundException extends Exception{
    public UserNotFoundException(String email) {
        super("User not found for email: " + email);
    }
}
