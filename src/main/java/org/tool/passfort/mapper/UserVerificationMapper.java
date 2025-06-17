package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.tool.passfort.model.UserVerification;

@Mapper
public interface UserVerificationMapper {
    /**
     * 插入用户验证信息
     * @param userVerification 用户验证信息
     * @return 插入的行数
     */
    int insertUserVerification(UserVerification userVerification);

    /**
     * 根据用户 ID 查询用户验证信息
     * @param userId 用户 ID
     * @return 用户验证信息
     */
    UserVerification selectByUserId(Integer userId);

    /**
     * 根据用户 ID 修改用户验证信息
     * @param userVerification 用户验证信息
     * @return 修改的行数
     */
    int updateUserVerification(UserVerification userVerification);
}
