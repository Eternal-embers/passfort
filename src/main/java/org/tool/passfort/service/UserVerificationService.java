package org.tool.passfort.service;

import org.tool.passfort.exception.*;
import org.tool.passfort.model.ActivationData;
import org.tool.passfort.model.UserVerification;

import java.util.List;

public interface UserVerificationService {
    /**
     * 创建用户验证信息
     * @param activationInformation 账户激活信息
     */
    void createUserVerification(ActivationData activationInformation) throws VerificationCodeExpireException, VerificationCodeErrorException;

    /**
     * 用户需要验证之前的身份信息或通过密码验证，才能修改用户验证信息
     * @param newUserVerification 用户验证信息
     */
    void updateUserVerification(UserVerification newUserVerification);

    /**
     * 根据用户 ID 获取用户验证信息
     */
    UserVerification getUserVerification(Integer userId);


    /**
     * 恢复邮箱验证
     * @param userId
     * @param verificationCode
     */
    void recoveryEmailVerification(Integer userId, String verificationCode, String codeKey) throws VerificationCodeExpireException, VerificationCodeErrorException;

    /**
     * 安全问题验证
     */
    void securityQuestionVerification(Integer userId, String securityAnswer1, String securityAnswer2, String securityAnswer3) throws SecurityQuestionVerificationException;

    /**
     * 个人信息验证
     */
    void personalInfoVerification(Integer userId, String fullName, String idCardNumber, String phoneNumber) throws PersonalInfoVerificationException;

    /**
     * 获取其他信息验证的参数列表
     */
    List<String> getOtherInfoVerificationParams(Integer userId);

    /**
     * 其他信息验证
     */
    void otherInfoVerification(Integer userId, String highSchoolName, String hometown, String occupation, String motherFullName, String fatherFullName) throws OtherInfoVerificationException;
}
