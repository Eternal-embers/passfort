package org.tool.passfort.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.tool.passfort.exception.DatabaseOperationException;
import org.tool.passfort.exception.PasswordHashingException;
import org.tool.passfort.service.UserService;
import org.tool.passfort.util.common.ResponseResult;

import java.util.Map;

@RestController("/api/users")
@ResponseResult
public class UserController {

    UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    //注册
    @PostMapping("/register")
    public String register(@RequestBody Map<String, String> request){
        String email = request.get("email");
        String password = request.get("password");

        try {
            boolean result = userService.registerUser(email, password);
            if(result) {
                return "register success";
            } else {
                //邮箱已经被注册
                return "email already registered!";
            }
        } catch (PasswordHashingException | DatabaseOperationException e) {
            return e.getMessage();
        }
    }

    //登录
}
