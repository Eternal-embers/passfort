package org.tool.passfort.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.tool.passfort.model.Credential;
import java.util.List;

@Mapper
public interface CredentialMapper {
    // 创建凭证
    int createCredential(@Param("userId") Integer userId, @Param("encryptionId") Integer encryptionId,
                         @Param("platform") String platform, @Param("account") String account);

    // 查询凭证
    List<Credential> queryCredential(@Param("userId") Integer userId, @Param("platform") String platform,
                                     @Param("account") String account, @Param("valid") Boolean valid);

    // 修改凭证
    int updateCredential(@Param("credentialId") Integer credentialId, @Param("platform") String platform,
                         @Param("account") String account, @Param("valid") Boolean valid);

    // 删除凭证（标记为失效的记录）
    int deleteCredential(@Param("credentialId") Integer credentialId);
}
