package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserVerification {
    private Integer verificationId; // 验证记录唯一标识
    private Integer userId; // 关联用户主表的用户ID
    private String recoveryEmail; // 恢复邮箱
    private String securityQuestion1; // 第一组安全问题
    private String securityAnswer1; // 第一组安全问题的答案（哈希存储）
    private String securityQuestion2; // 第二组安全问题
    private String securityAnswer2; // 第二组安全问题的答案（哈希存储）
    private String securityQuestion3; // 第三组安全问题
    private String securityAnswer3; // 第三组安全问题的答案（哈希存储）
    private String fullName; // 姓名(哈希存储)
    private String idCardNumber; // 身份证号（哈希存储）
    private String phoneNumber; // 手机号（哈希存储）
    private String highSchoolName; // 高中名称(哈希存储)
    private String hometown; // 家乡(哈希存储)
    private String occupation; // 工作(哈希存储)
    private String motherFullName; // 母亲姓名(哈希存储)
    private String fatherFullName; // 父亲姓名(哈希存储)
}