package org.tool.passfort.exception;

import java.time.LocalDateTime;

public class AccountLockedException extends Exception{
    public LocalDateTime lockoutUntil;

    public AccountLockedException(String email, LocalDateTime lockoutUntil) {
        super("Account locked for email: " + email + ". Lockout until: " + lockoutUntil);
        this.lockoutUntil = lockoutUntil;
    }

    public LocalDateTime getLockoutUntil() {
        return lockoutUntil;
    }
}
