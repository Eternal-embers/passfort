package org.tool.passfort.exception;

import java.time.LocalDateTime;

public class AccountLockedException extends Exception{
    public AccountLockedException(String email, LocalDateTime lockoutUntil) {
        super("Account locked for email: " + email + ". Lockout until: " + lockoutUntil);
    }
}
