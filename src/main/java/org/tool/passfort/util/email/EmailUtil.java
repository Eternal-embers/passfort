package org.tool.passfort.util.email;


import freemarker.template.TemplateException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * 邮件工具接口，提供邮件发送功能。
 */
public interface EmailUtil {
    // 重试次数和重试间隔时间（单位：毫秒）
    int MAX_RETRIES = 3;
    long RETRY_INTERVAL = 1000; // 2秒

    /**
     * 发送简单的纯文本邮件。
     *
     * @param to      收件人的邮箱地址。
     * @param subject 邮件主题。
     * @param body    邮件正文（纯文本格式）。
     * @return 如果邮件发送成功返回 true，否则返回 false。
     */
    boolean sendEmail(String to, String subject, String body) throws MessagingException, IOException;

    /**
     * 发送带附件的邮件。
     *
     * @param to        收件人的邮箱地址。
     * @param subject   邮件主题。
     * @param body      邮件正文（纯文本格式）。
     * @param filePath  要附加的文件路径。
     * @return 如果邮件发送成功返回 true，否则返回 false。
     */
    boolean sendEmailWithAttachment(String to, String subject, String body, String filePath) throws MessagingException, IOException;

    /**
     * 发送 HTML 内容的邮件。
     *
     * @param to         收件人的邮箱地址。
     * @param subject    邮件主题。
     * @param htmlContent 邮件正文（HTML 格式）。
     * @return 如果邮件发送成功返回 true，否则返回 false。
     */
    boolean sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException, IOException;

    /**
     * 向多个收件人发送邮件。
     *
     * @param to       收件人邮箱地址列表。
     * @param subject  邮件主题。
     * @param content  邮件正文（纯文本格式）。
     * @param filePath 要附加的文件路径。
     * @param isHtml   邮件内容是否是 HTML 格式。
     * @return 如果所有邮件都发送成功返回 true，否则返回 false。
     */
    Map<String, Boolean> sendBatchEmail(List<String> to, String subject, String content, String filePath, boolean isHtml);

    /**
     * 创建用于发送邮件的 MimeMessage 实例。
     * 该方法可以在实现类中被重写，以自定义邮件内容的创建过程。
     *
     * @param session   JavaMail 会话实例。
     * @param to        收件人的邮箱地址。
     * @param subject   邮件主题。
     * @param content   邮件内容。
     * @param filePath  要附加的文件路径（如果没有附件，可以为 null）。
     * @param isHtml    是否是 HTML 内容。
     * @return MimeMessage 实例。
     * @throws MessagingException 如果创建邮件时发生错误。
     */
    MimeMessage createMessage(jakarta.mail.Session session, String to, String subject, String content, String filePath, boolean isHtml) throws MessagingException, IOException;

    /**
     * 创建 JavaMail 会话实例。
     * 该方法可以在实现类中被重写，以自定义会话的创建过程。
     *
     * @return JavaMail 会话实例。
     */
    jakarta.mail.Session createSession();

    /**
     * 使用邮件模板发送邮件。
     * 根据模板路径加载模板内容，并替换模板参数后发送邮件。
     *
     * @param to             收件人的邮箱地址。
     * @param subject        邮件主题。
     * @param templatePath   邮件模板文件路径。
     * @param templateParams 模板参数（键值对形式，用于替换模板中的占位符）。
     * @param filePath       要附加的文件路径（如果没有附件，可以为 null）。
     * @return 如果邮件发送成功返回 true，否则返回 false。
     * @throws MessagingException 如果邮件发送过程中发生错误。
     * @throws IOException       如果读取模板文件时发生 I/O 错误。
     */
    public boolean sendEmailWithTemplate(String to, String subject, String templatePath, Map<String, String> templateParams, String filePath) throws MessagingException, IOException, TemplateException, URISyntaxException;

    /**
     * 异步发送邮件。
     * 使用线程池异步执行邮件发送任务，避免阻塞主线程。
     *
     * @param to      收件人的邮箱地址。
     * @param subject 邮件主题。
     * @param body    邮件正文。
     * @return
     * @throws MessagingException 如果邮件发送过程中发生错误。
     * @throws IOException        如果读取邮件内容时发生 I/O 错误。
     */
    CompletableFuture<Boolean> sendEmailAsync(String to, String subject, String body, String filePath, boolean isHtml) throws MessagingException, IOException;
}