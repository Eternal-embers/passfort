package org.tool.passfort.exception;

public class AccountNotActiveException extends Exception{
    public AccountNotActiveException(String email) {
        super("Account not active for email: " + email);
    }
}
