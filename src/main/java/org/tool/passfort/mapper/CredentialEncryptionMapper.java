package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.tool.passfort.model.CredentialEncryption;

@Mapper
public interface CredentialEncryptionMapper {
    // 创建加密信息
    void createCredentialEncryption(@Param("iv") byte[] iv,
                                    @Param("secretKey") byte[] secretKey,
                                    @Param("encryptedPassword") byte[] encryptedPassword);

    // 根据ID查询加密信息
    CredentialEncryption selectCredentialEncryptionById(@Param("encryptionId") Integer encryptionId);
}
