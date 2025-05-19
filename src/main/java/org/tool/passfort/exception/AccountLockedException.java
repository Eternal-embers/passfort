package org.tool.passfort.exception;

import java.time.LocalDateTime;

public class AccountLockedException extends Exception{
    public LocalDateTime LockoutUntil;

    public AccountLockedException(String email, LocalDateTime LockoutUntil) {
        super("Account locked for email: " + email + ". Lockout until: " + LockoutUntil);
        this.LockoutUntil = LockoutUntil;
    }

    public LocalDateTime getLockoutUntil() {
        return LockoutUntil;
    }
}
