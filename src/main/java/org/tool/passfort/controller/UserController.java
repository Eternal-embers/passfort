package org.tool.passfort.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.tool.passfort.exception.*;
import org.tool.passfort.model.LoginResponse;
import org.tool.passfort.service.UserService;
import org.tool.passfort.model.ApiResponse;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    //注册
    @PostMapping("/register")
    public ApiResponse register(@RequestBody Map<String, String> request) throws DatabaseOperationException, PasswordHashingException, EmailAlreadyRegisteredException {
        String email = request.get("email");
        String password = request.get("password");

        userService.registerUser(email, password);

        return ApiResponse.success(email + " register success");
    }

    //激活帐号
    @PostMapping("/activate")
    public ApiResponse activate(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        userService.activateUser(email);

        return ApiResponse.success("activate " + email + " success");
    }

    //登录
    @PostMapping("/login")
    public ApiResponse login(@RequestBody Map<String, String> request) throws UserNotFoundException, AccountLockedException, VerifyPasswordFailedException, AccountNotActiveException, PasswordInvalidException {
        String email = request.get("email");
        String password = request.get("password");

        LoginResponse loginResponse = userService.loginUser(email, password);

        return ApiResponse.success(loginResponse);
    }

    @GetMapping("/jwt")
    public ApiResponse testJwt() {
        // 持有合法 JWT 令牌
        return ApiResponse.success("request success");
    }
}
