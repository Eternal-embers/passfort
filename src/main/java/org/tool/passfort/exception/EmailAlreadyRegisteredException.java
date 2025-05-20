package org.tool.passfort.exception;

public class EmailAlreadyRegisteredException extends Exception{
    public EmailAlreadyRegisteredException(String email) {
        super("Email already registered: " + email);
    }

}
