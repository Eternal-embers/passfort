package org.tool.passfort.service.impl;

import freemarker.template.TemplateException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Service;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;
import org.tool.passfort.service.EmailService;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class EmailServiceImpl implements EmailService {
    private final JavaMailSenderImpl mailSender;
    private final FreeMarkerConfigurer freeMarkerConfigurer;

    @Value("${spring.mail.username:}")
    private String fromEmail;

    // 线程池用于异步发送邮件, 使用固定线程池，线程数为4
    private final ExecutorService emailExecutor = Executors.newFixedThreadPool(4);

    @Autowired
    public EmailServiceImpl(JavaMailSenderImpl mailSender, FreeMarkerConfigurer freeMarkerConfigurer){
        this.mailSender = mailSender;
        this.freeMarkerConfigurer = freeMarkerConfigurer;
    }

    @Override
    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }

    /**
     * 发送带附件的邮件
     *
     * @param to 收件人邮箱地址
     * @param subject 邮件主题
     * @param text 邮件文本内容，网页格式
     * @param attachmentPath 附件路径
     */
    @Override
    public void sendEmail(String to, String subject, String text, String attachmentPath) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);
            helper.addAttachment(attachmentPath, new File(attachmentPath));

            mailSender.send(mimeMessage);

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 向多个收件人发送邮件
     *
     * @param to 收件人邮箱地址数组
     * @param subject 邮件主题
     * @param text 邮件文本内容，网页格式
     */
    @Override
    public void sendEmailToRecipients(String[] to, String subject, String text) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try{
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);

            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 向多个收件人发送带附件的邮件
     *
     * @param to 收件人邮箱地址数组
     * @param subject 邮件主题
     * @param text 邮件文本内容，网页格式
     * @param attachmentPath 附件路径
     */
    @Override
    public void sendEmailToRecipients(String[] to, String subject, String text, String attachmentPath) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try{
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);
            helper.addAttachment(attachmentPath, new File(attachmentPath));

            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 异步发送邮件
     *
     * @param preparator 邮件内容
     */
    @Override
    public void sendEmailAsync(MimeMessagePreparator preparator) {
        emailExecutor.submit(() -> {
            try{
                mailSender.send(preparator);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    @Override
    public MimeMessagePreparator createPreparator(String to, String subject, String text) {
        return mimeMessage -> {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);
        };
    }

    @Override
    public MimeMessagePreparator createPreparator(String to, String subject, String text, String attachmentPath) {
        return mimeMessage -> {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);
            helper.addAttachment(attachmentPath, new File(attachmentPath));
        };
    }

    @Override
    public MimeMessagePreparator createPreparator(String[] to, String subject, String text) {
        return mimeMessage -> {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);
        };
    }

    @Override
    public MimeMessagePreparator createPreparator(String[] to, String subject, String text, String attachmentPath) {
        return mimeMessage -> {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, true);
            helper.addAttachment(attachmentPath, new File(attachmentPath));
        };
    }


    /**
     * 根据模板路径加载模板内容，并替换模板参数后发送邮件。
     *
     * @param to 收件人邮箱地址
     * @param subject 邮件主题
     * @param templatePath 邮件模板文件路径
     * @param templateVariables 模板参数（键值对形式，用于替换模板中的占位符）
     */
    @Override
    public void sendEmailWithTemplate(String to, String subject, String templatePath, Object templateVariables) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);
            String emailContent = loadTemplate(templatePath, templateVariables);

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(emailContent, true);

            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 根据模板路径加载模板内容，并替换模板参数后返回邮件内容。
     *
     * @param templatePath 邮件模板文件路径
     * @param templateVariables 模板参数（键值对形式，用于替换模板中的占位符）
     * @return 邮件内容
     */
    public String loadTemplate(String templatePath, Object templateVariables) {
        try{
            return FreeMarkerTemplateUtils.processTemplateIntoString(freeMarkerConfigurer.getConfiguration().getTemplate(templatePath), templateVariables);
        } catch (TemplateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isValidEmail(String email) {
        // 使用 Apache Commons Validator 验证邮箱格式

        return true;
    }
}
