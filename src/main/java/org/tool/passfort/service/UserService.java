package org.tool.passfort.service;

import org.tool.passfort.exception.*;

import java.time.LocalDateTime;

public interface UserService {
    boolean registerUser(String email, String password) throws PasswordHashingException, DatabaseOperationException;
    String loginUser(String email, String password) throws AccountNotActiveException, AccountLockedException, UserNotFoundException, VerifyPasswordFailedException;
    boolean resetPassword(String email, String newPassword);
    boolean activateUser(String email);
    boolean lockAccount(String email, LocalDateTime lockoutUntil);
    String refreshToken(String token);
}

