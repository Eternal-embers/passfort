package org.tool.passfort.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.tool.passfort.exception.*;
import org.tool.passfort.mapper.UserVerificationMapper;
import org.tool.passfort.model.ActivationInformation;
import org.tool.passfort.model.UserVerification;
import org.tool.passfort.service.UserVerificationService;
import org.tool.passfort.util.redis.RedisUtil;
import org.tool.passfort.util.secure.HashUtil;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional(rollbackFor = DatabaseOperationException.class)
public class UserVerificationServiceImpl implements UserVerificationService {
    private static final Logger logger = LoggerFactory.getLogger(UserVerificationServiceImpl.class);
    private final UserVerificationMapper userVerificationMapper;
    private final RedisUtil redisUtil;

    @Autowired
    public UserVerificationServiceImpl(UserVerificationMapper userVerificationMapper, RedisUtil redisUtil){
        this.userVerificationMapper = userVerificationMapper;
        this.redisUtil = redisUtil;
    }

    @Override
    public void createUserVerification(ActivationInformation activationInformation) throws VerificationCodeExpireException, VerificationCodeErrorException {
        UserVerification userVerification = activationInformation.getUserVerification();
        String recoveryEmail = userVerification.getRecoveryEmail();
        String verificationCode = activationInformation.getVerificationCode();
        String codeKey = activationInformation.getCodeKey();

        //检查 codeKey 是否过期
        boolean isExpire = redisUtil.isExpire(codeKey);
        if(isExpire) {
            logger.error("verification code expired for codeKey: {}", codeKey);
            throw new VerificationCodeExpireException("Verification code expired");
        }

        //检查验证码是否正确
        String verificationInfo = (String) redisUtil.get(codeKey);// 验证信息的格式为"邮箱:验证码"
        if(!verificationInfo.equals(recoveryEmail + ":" + verificationCode)) {
            logger.error("verification code error for codeKey: {}", codeKey);
            throw new VerificationCodeErrorException("Verification code error");
        }

        // 处理敏感字段
        hashSensitiveData(userVerification);

        // 处理完敏感数据后，创建用户身份验证信息
        userVerificationMapper.insertUserVerification(userVerification);
    }

    /**
     *  对用户验证信息的敏感数据进行处理, 假设能确保 userVerification 中的字段都不为空
     */
    private void hashSensitiveData(UserVerification userVerification){
        /* 对敏感数据进行哈希处理 */
        // 必选项
        userVerification.setSecurityAnswer1(HashUtil.hashText(userVerification.getSecurityAnswer1())); // 安全问题1
        userVerification.setSecurityAnswer2(HashUtil.hashText(userVerification.getSecurityAnswer2())); // 安全问题2
        userVerification.setSecurityAnswer3(HashUtil.hashText(userVerification.getSecurityAnswer3())); // 安全问题3
        userVerification.setFullName(HashUtil.hashText(userVerification.getFullName())); // 姓名
        userVerification.setIdCardNumber(HashUtil.hashText(userVerification.getIdCardNumber())); // 身份证号
        userVerification.setPhoneNumber(HashUtil.hashText(userVerification.getPhoneNumber())); // 手机号

        // 可选项
        if(!userVerification.getHighSchoolName().isEmpty()) {
            userVerification.setHighSchoolName(HashUtil.hashText(userVerification.getHighSchoolName())); // 高中名称
        }

        if(!userVerification.getHometown().isEmpty()) {
            userVerification.setHometown(HashUtil.hashText(userVerification.getHometown())); // 家乡
        }

        if(!userVerification.getOccupation().isEmpty()) {
            userVerification.setOccupation(HashUtil.hashText(userVerification.getOccupation())); // 工作
        }

        if(!userVerification.getFatherFullName().isEmpty()) {
            userVerification.setFatherFullName(HashUtil.hashText(userVerification.getFatherFullName())); // 父亲名称
        }

        if(!userVerification.getMotherFullName().isEmpty()) {
            userVerification.setMotherFullName(HashUtil.hashText(userVerification.getMotherFullName())); // 母亲名称
        }
    }

    /**
     * 用户需要验证之前的身份信息或通过密码验证，才能修改用户验证信息
     * @param newUserVerification 用户验证信息
     */
    @Override
    public void updateUserVerification(UserVerification newUserVerification) {
        // 对敏感字段进行哈希处理
        hashSensitiveData(newUserVerification);

        // 更新用户验证信息
        userVerificationMapper.updateUserVerification(newUserVerification);
    }

    @Override
    public UserVerification getUserVerification(Integer userId) {
        return userVerificationMapper.selectByUserId(userId);
    }

    @Override
    public void recoveryEmailVerification(Integer userId, String verificationCode, String codeKey) throws VerificationCodeExpireException, VerificationCodeErrorException {
        UserVerification userVerification = userVerificationMapper.selectByUserId(userId);

        String recoveryEmail = userVerification.getRecoveryEmail();

        //检查 codeKey 是否过期
        boolean isExpire = redisUtil.isExpire(codeKey);
        if(isExpire) {
            logger.error("verification code expired for codeKey: {}", codeKey);
            throw new VerificationCodeExpireException("Verification code expired");
        }

        //检查验证码是否正确
        String verificationInfo = (String) redisUtil.get(codeKey);// 验证信息的格式为"邮箱:验证码"
        if(!verificationInfo.equals(recoveryEmail + ":" + verificationCode)) {
            logger.error("verification code error for codeKey: {}", codeKey);
            throw new VerificationCodeErrorException("Verification code error");
        }

        // 不抛出异常则验证成功
    }

    @Override
    public void securityQuestionVerification(Integer userId, String securityAnswer1, String securityAnswer2, String securityAnswer3) throws SecurityQuestionVerificationException {
        UserVerification userVerification = userVerificationMapper.selectByUserId(userId);

        boolean res1 = HashUtil.verifyTextHash(securityAnswer1, userVerification.getSecurityAnswer1());
        if(!res1) {
            throw new SecurityQuestionVerificationException("Security Answer 1 is incorrect. Security question verification failed.", 1);
        }

        boolean res2 = HashUtil.verifyTextHash(securityAnswer2, userVerification.getSecurityAnswer2());
        if(!res2) {
            throw new SecurityQuestionVerificationException("Security Answer 2 is incorrect. Security question verification failed.", 2);
        }

        boolean res3 = HashUtil.verifyTextHash(securityAnswer3, userVerification.getSecurityAnswer3());
        if(!res3) {
            throw new SecurityQuestionVerificationException("Security Answer 3 is incorrect. Security question verification failed.", 3);
        }

        // 不抛出异常则验证成功
    }

    @Override
    public void personalInfoVerification(Integer userId, String fullName, String idCardNumber, String phoneNumber) throws PersonalInfoVerificationException {
        UserVerification userVerification = userVerificationMapper.selectByUserId(userId);
        boolean fullNameRes = HashUtil.verifyTextHash(fullName, userVerification.getFullName());

        if(!fullNameRes) {
            throw new PersonalInfoVerificationException("Full name is incorrect. Personal information verification failed.", "fullName");
        }

        boolean idCardNumberRes = HashUtil.verifyTextHash(idCardNumber, userVerification.getIdCardNumber());
        if(!idCardNumberRes) {
            throw new PersonalInfoVerificationException("IdCard number is incorrect. Personal information verification failed.", "idCardNumber");
        }

        boolean phoneNumberRes = HashUtil.verifyTextHash(phoneNumber, userVerification.getPhoneNumber());
        if(!phoneNumberRes) {
            throw new PersonalInfoVerificationException("Phone number is incorrect. Personal information verification failed.", "phoneNumber");
        }

        // 不抛出异常则验证成功
    }

    @Override
    public List<String> getOtherInfoVerificationParams(Integer userId) {
        UserVerification userVerification = userVerificationMapper.selectByUserId(userId);
        List<String> fieldNames = new ArrayList<>();

        if (userVerification != null) {
            if (userVerification.getHighSchoolName() != null && !userVerification.getHighSchoolName().isEmpty()) {
                fieldNames.add("highSchoolName");
            }
            if (userVerification.getHometown() != null && !userVerification.getHometown().isEmpty()) {
                fieldNames.add("homeTown");
            }
            if (userVerification.getOccupation() != null && !userVerification.getOccupation().isEmpty()) {
                fieldNames.add("occupation");
            }
            if (userVerification.getMotherFullName() != null && !userVerification.getMotherFullName().isEmpty()) {
                fieldNames.add("motherFullName");
            }
            if (userVerification.getFatherFullName() != null && !userVerification.getFatherFullName().isEmpty()) {
                fieldNames.add("fatherFullName");
            }
        }

        return fieldNames;
    }

    @Override
    public void otherInfoVerification(Integer userId, String highSchoolName, String hometown, String occupation, String motherFullName, String fatherFullName) throws OtherInfoVerificationException {
        UserVerification userVerification = userVerificationMapper.selectByUserId(userId);

        if(!hometown.isEmpty()){
            boolean homeTownRes = HashUtil.verifyTextHash(hometown, userVerification.getHometown());
            if(!homeTownRes) {
                throw new OtherInfoVerificationException("Home town is incorrect, other information verification failed", "homeTown");
            }
        }


        if(!occupation.isEmpty()){
            boolean occupationRes = HashUtil.verifyTextHash(hometown, userVerification.getOccupation());
            if(!occupationRes) {
                throw new OtherInfoVerificationException("Occupation is incorrect, other information verification failed", "occupation");
            }
        }

        if(!motherFullName.isEmpty()) {
            boolean motherFullNameRes = HashUtil.verifyTextHash(motherFullName, userVerification.getMotherFullName());
            if(!motherFullNameRes) {
                throw new OtherInfoVerificationException("Mother full name is incorrect, other information verification failed", "motherFullName");
            }
        }

        if(!fatherFullName.isEmpty()) {
            boolean fatherFullNameRes = HashUtil.verifyTextHash(fatherFullName, userVerification.getFatherFullName());
            if(!fatherFullNameRes) {
                throw new OtherInfoVerificationException("Father full name is incorrect, other information verification failed", "fatherFullName");
            }
        }

        // 不抛出异常则验证成功
    }
}
