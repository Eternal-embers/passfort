package org.tool.passfort.service;

import org.springframework.mail.javamail.MimeMessagePreparator;

public interface EmailService {
    /**
     * 发送简单的文本邮件
     * @param to 收件人
     * @param subject 主题
     * @param text 文本内容
     */
    void sendEmail(String to, String subject, String text);

    // 发送带附件的邮件

    /**
     * 发送带附件的邮件，邮件内容为网页
     * @param to 收件人
     * @param subject 主题
     * @param text 网页内容
     * @param attachmentPath 附件路径
     */
    void sendEmail(String to, String subject, String text, String attachmentPath);

    /**
     * 向多个收件人发送网页邮件
     * @param to 收件人邮箱地址数组
     * @param subject 邮件主题
     * @param text 邮件文本内容，网页格式
     */
    void sendEmailToRecipients(String[] to, String subject, String text);

    /**
     * 向多个收件人发送带附件的邮件，邮件内容为网页
     * @param to 收件人邮箱地址数组
     * @param subject 邮件主题
     * @param text 网页内容
     * @param attachmentPath 附件路径
     */
    void sendEmailToRecipients(String[] to, String subject, String text, String attachmentPath);

    /**
     * 异步发送邮件
     * @param preparator 邮件的准备器
     */
    void sendEmailAsync(MimeMessagePreparator preparator);

    /**
     * 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
     * @param to 收件人
     * @param subject 主题
     * @param text 网页内容
     * @return 邮件准备器
     */
    MimeMessagePreparator createPreparator(String to, String subject, String text);

    /**
     * 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
     * @param to 收件人
     * @param subject 主题
     * @param text 网页内容
     * @param attachmentPath 附件路径
     * @return 邮件准备器
     */
    MimeMessagePreparator createPreparator(String to, String subject, String text, String attachmentPath);

    /**
     * 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
     * @param to 收件人邮箱地址数组
     * @param subject 主题
     * @param text 网页内容
     * @return 邮件准备器
     */
    MimeMessagePreparator createPreparator(String[] to, String subject, String text);

    /**
     * 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
     * @param to 收件人邮箱地址数组
     * @param subject 主题
     * @param text 网页内容
     * @param attachmentPath 附件路径
     * @return 邮件准备器
     */
    MimeMessagePreparator createPreparator(String[] to, String subject, String text, String attachmentPath);

    /**
     * 根据模板路径加载模板内容，并替换模板参数后发送邮件。
     * @param to 收件人邮箱地址
     * @param subject 邮件主题
     * @param templatePath 邮件模板文件路径
     * @param templateVariables 模板参数（键值对形式，用于替换模板中的占位符）
     */
    void sendEmailWithTemplate(String to, String subject, String templatePath, Object templateVariables);

    /**
     * 根据模板路径加载模板内容，并替换模板参数后返回邮件内容。
     * @param templatePath 邮件模板文件路径
     * @param templateVariables 模板参数（键值对形式，用于替换模板中的占位符）
     * @return 邮件内容
     */
    String loadTemplate(String templatePath, Object templateVariables);

    /**
     * 验证邮箱格式
     * @param email 邮箱地址
     * @return 如果邮箱格式正确返回 true，否则返回 false
     */
    boolean isValidEmail(String email);
}
