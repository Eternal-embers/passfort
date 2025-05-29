package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.tool.passfort.model.Credential;
import java.util.List;

@Mapper
public interface CredentialMapper {
    // 创建凭证
    Integer createCredential(Credential credential);

    // 根据凭证 ID 查询凭证
    Credential queryCredentialById(@Param("credentialId") Integer credentialId);

    // 根据凭证 ID 查询用户ID
    Integer queryUserIdByCredentialId(@Param("credentialId") Integer credentialId);

    // 根据凭证加密信息 ID 查询用户ID
    Integer queryUserIdByEncryptionId(@Param("encryptionId") Integer encryptionId);

    // 获取所有的平台名称
    List<String> getAllPlatforms(@Param("userId") Integer userId);

    // 查询凭证
    List<Credential> queryCredential(@Param("userId") Integer userId, @Param("platform") String platform,
                                     @Param("account") String account, @Param("valid") Boolean valid);

    // 修改密码
    int updateCredentialEncryption(@Param("credentialId") Integer credentialId, @Param("encryptionId") Integer encryptionId);

    // 修改凭证
    int updateCredential(@Param("credentialId") Integer credentialId, @Param("platform") String platform,
                         @Param("account") String account, @Param("valid") Boolean valid);

    // 删除凭证（标记为失效的记录）
    int deleteCredential(@Param("credentialId") Integer credentialId);
}
