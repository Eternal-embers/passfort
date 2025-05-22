package org.tool.passfort.service;

import org.tool.passfort.exception.*;
import org.tool.passfort.dto.LoginResponse;

import java.time.LocalDateTime;

public interface UserService {
    void registerUser(String email, String password) throws PasswordHashingException, DatabaseOperationException, EmailAlreadyRegisteredException;
    LoginResponse loginUser(String email, String password) throws AccountNotActiveException, AccountLockedException, UserNotFoundException, VerifyPasswordFailedException, PasswordInvalidException;
    boolean resetPassword(String email, String newPassword) throws PasswordRepeatException;
    boolean activateUser(String email);
    boolean lockAccount(String email, LocalDateTime lockoutUntil);

    boolean isAccountLocked(String email);

    LocalDateTime getLockoutUntil(String email);

    String getNewAccessToken(String refreshToken) throws AuthenticationExpiredException;

    String getNewRefreshToken(String refreshToken) throws AuthenticationExpiredException;

    boolean isRefreshTokenExpiringSoon(String refreshToken);

    void logout(String refreshToken);
}

