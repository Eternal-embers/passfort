package org.tool.passfort.service;

import org.springframework.mail.javamail.MimeMessagePreparator;

public interface EmailService {
    // 发送简单纯文本邮件
    void sendEmail(String to, String subject, String text);

    // 发送带附件的邮件
    void sendEmail(String to, String subject, String text, String attachmentPath);

    // 向多个收件人发送邮件
    void sendEmailToRecipients(String[] to, String subject, String text);

    // 向多个收件人发送带附件的邮件
    void sendEmailToRecipients(String[] to, String subject, String text, String attachmentPath);

    // 异步发送邮件
    void sendEmailAsync(MimeMessagePreparator preparator);

    // 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
    MimeMessagePreparator createPreparator(String to, String subject, String text);

    // 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
    MimeMessagePreparator createPreparator(String to, String subject, String text, String attachmentPath);

    // 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
    MimeMessagePreparator createPreparator(String[] to, String subject, String text);

    // 配合 sendEmailAsync 使用，创建 MimeMessagePreparator
    MimeMessagePreparator createPreparator(String[] to, String subject, String text, String attachmentPath);

    // 使用网页模板发送邮件
    void sendEmailWithTemplate(String to, String subject, String templatePath, Object templateVariables);

    String loadTemplate(String templatePath, Object templateVariables);

    boolean isValidEmail(String email);
}
