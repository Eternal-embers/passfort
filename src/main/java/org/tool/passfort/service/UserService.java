package org.tool.passfort.service;

import org.tool.passfort.exception.*;
import org.tool.passfort.model.LoginResponse;

import java.time.LocalDateTime;

public interface UserService {
    void registerUser(String email, String password) throws PasswordHashingException, DatabaseOperationException, EmailAlreadyRegisteredException;
    LoginResponse loginUser(String email, String password) throws AccountNotActiveException, AccountLockedException, UserNotFoundException, VerifyPasswordFailedException, PasswordInvalidException;
    boolean resetPassword(String email, String newPassword);
    boolean activateUser(String email);
    boolean lockAccount(String email, LocalDateTime lockoutUntil);
    String refreshToken(String token);
}

