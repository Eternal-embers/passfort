package org.tool.passfort.util.email.impl;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.springframework.beans.factory.annotation.Value;
import org.tool.passfort.util.email.EmailUtil;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class SmtpEmailUtil implements EmailUtil {
    @Value("${mail.smtp.host}")
    private String smtpHost;

    @Value("${mail.smtp.starttls.enable}")
    private String startTlsEnable;

    @Value("${mail.smtp.user}")
    private String username;

    @Value("${mail.smtp.pass}")
    private String password;

    @Value("${mail.templates}")
    private String templateDir;

    private String smtpAuth;

    // 动态设置的端口号
    private String smtpPort;

    // 创建一个共享的线程池
    private static final ExecutorService executor = Executors.newCachedThreadPool();

    static {
        // 注册关闭钩子
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            executor.shutdown(); // 尝试关闭线程池
            try {
                if (!executor.awaitTermination(60, TimeUnit.SECONDS)) { // 等待线程池中的任务完成
                    executor.shutdownNow(); // 强制关闭线程池
                }
            } catch (InterruptedException e) {
                executor.shutdownNow(); // 强制关闭线程池
                Thread.currentThread().interrupt(); // 重新设置中断状态
            }
        }));
    }

    public SmtpEmailUtil() {
        smtpAuth = "true"; // 默认开启 SMTP 认证

        // 根据邮箱类型和加密方式动态设置端口号
        if ("smtp.qq.com".equalsIgnoreCase(smtpHost)) {
            // QQ邮箱
            smtpPort = startTlsEnable.equalsIgnoreCase("true") ? "587" : "465";
        } else if ("smtp.163.com".equalsIgnoreCase(smtpHost)) {
            // 163邮箱
            smtpPort = startTlsEnable.equalsIgnoreCase("true") ? "587" : "465";
        } else if ("smtp.exmail.qq.com".equalsIgnoreCase(smtpHost)) {
            // QQ企业邮箱
            smtpPort = startTlsEnable.equalsIgnoreCase("true") ? "587" : "465";
        } else if ("smtp.gmail.com".equalsIgnoreCase(smtpHost)) {
            // Gmail
            smtpPort = "587"; // Gmail仅支持SSL/TLS，端口为587
        } else if ("smtp.126.com".equalsIgnoreCase(smtpHost)) {
            // 126邮箱
            smtpPort = "25"; // 126邮箱默认端口为25，不支持SSL
        } else if ("smtp.139.com".equalsIgnoreCase(smtpHost)) {
            // 139邮箱
            smtpPort = "25"; // 139邮箱默认端口为25，不支持SSL
        } else if ("smtp.foxmail.com".equalsIgnoreCase(smtpHost)) {
            // 狐邮(Foxmail)
            smtpPort = "25"; // 狐邮默认端口为25，不支持SSL
        } else if ("smtp.sina.com".equalsIgnoreCase(smtpHost)) {
            // 新浪邮箱
            smtpPort = "25"; // 新浪邮箱默认端口为25，不支持SSL
        } else {
            // 默认端口，可自定义
            smtpPort = "25";
        }
    }

    public Session createSession() {
        Properties properties = new Properties();
        properties.put("mail.smtp.host", smtpHost);
        properties.put("mail.smtp.port", smtpPort);
        properties.put("mail.smtp.auth", smtpAuth);
        properties.put("mail.smtp.starttls.enable", startTlsEnable);
        return Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
    }

    public MimeMessage createMessage(Session session, String to, String subject, String content, String filePath, boolean isHtml) throws MessagingException, IOException {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(username));
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        message.setSubject(subject);

        if (filePath == null || filePath.isEmpty()) {
            if (isHtml) {
                message.setContent(content, "text/html;charset=UTF-8");
            } else {
                message.setText(content);
            }
        } else {
            MimeMultipart multipart = new MimeMultipart();
            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(content);
            multipart.addBodyPart(textPart);

            File file = new File(filePath);
            if (file.exists()) {
                if (!file.isFile()) {
                    throw new IllegalArgumentException("The provided path is not a file: " + filePath);
                }
                if (!file.canRead()) {
                    throw new SecurityException("File cannot be read: " + filePath);
                }

                MimeBodyPart attachmentPart = new MimeBodyPart();
                attachmentPart.attachFile(file);
                attachmentPart.setFileName(file.getName());
                multipart.addBodyPart(attachmentPart);
            } else {
                throw new IllegalArgumentException("File does not exist: " + filePath);
            }

            message.setContent(multipart);
        }

        return message;
    }

    public boolean sendEmail(String to, String subject, String content, String filePath, boolean isHtml) throws MessagingException, IOException {
        // 创建邮件会话
        Session session = createSession();

        // 创建邮件内容
        MimeMessage message;
        try {
            message = createMessage(session, to, subject, content, filePath, isHtml);
        } catch (MessagingException e) {
            throw new RuntimeException("Creating email message failed", e);
        }

        // 配置重试策略
        RetryConfig retryConfig = RetryConfig.custom()
                .maxAttempts(MAX_RETRIES) // 设置最大重试次数
                .waitDuration(Duration.ofMillis(RETRY_INTERVAL)) // 设置每次重试之间的等待时间
                .build();

        // 创建重试实例
        RetryRegistry registry = RetryRegistry.of(retryConfig);
        Retry retry = registry.retry("emailRetry"); // 创建一个名为 "emailRetry" 的重试实例

        // 尝试发送邮件
        try {
            retry.executeRunnable(() -> {
                try {
                    // 使用 Transport.send 方法发送邮件
                    Transport.send(message);
                } catch (MessagingException e) {
                    // 如果发送邮件时发生异常，抛出运行时异常
                    throw new RuntimeException("Sending email to " + to + " failed", e);
                }
            });
            // 如果邮件发送成功，返回 true
            return true;
        } catch (Exception e) {
            System.err.println("Email sending failed after " + MAX_RETRIES + " attempts: " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean sendEmail(String to, String subject, String body) throws MessagingException, IOException {
        return sendEmail(to, subject, body, null, false);
    }

    @Override
    public boolean sendEmailWithAttachment(String to, String subject, String body, String filePath) throws MessagingException, IOException {
        return sendEmail(to, subject, body, filePath, false);
    }

    @Override
    public boolean sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException, IOException {
        return sendEmail(to, subject, htmlContent, null, true);
    }

    @Override
    public Map<String, Boolean> sendBatchEmail(List<String> to, String subject, String content, String filePath, boolean isHtml) {
        Map<String, Boolean> sendStatus = new HashMap<>(); // 用于记录每个邮件的发送状态
        AtomicInteger completedEmails = new AtomicInteger(0); // 用于跟踪已完成的邮件数量
        try {
            // 创建邮件会话
            Session session = createSession();

            // 配置重试策略
            RetryConfig retryConfig = RetryConfig.custom()
                    .maxAttempts(MAX_RETRIES) // 设置最大重试次数
                    .waitDuration(Duration.ofMillis(RETRY_INTERVAL)) // 设置每次重试之间的等待时间
                    .build();

            // 创建重试实例
            RetryRegistry registry = RetryRegistry.of(retryConfig);
            Retry retry = registry.retry("emailRetry"); // 创建一个名为 "emailRetry" 的重试实例

            // 连接到SMTP服务器
            Transport transport = session.getTransport();
            transport.connect(smtpHost, username, password);

            // 遍历收件人列表，为每个收件人发送邮件
            for (String email : to) {
                if (!transport.isConnected()) {
                    transport.connect(smtpHost, username, password);
                }

                // 创建邮件内容
                MimeMessage message = createMessage(session, email, subject, content, filePath, isHtml);

                // 尝试发送邮件，使用重试逻辑
                try {
                    retry.executeRunnable(() -> {
                        try {
                            //在同一个 Transport 对象上发送多封邮件，从而减少连接和断开的开销。
                            transport.sendMessage(message, message.getAllRecipients());

                            // 如果邮件发送成功，记录状态为 true
                            sendStatus.put(email, true);

                            // 每完成一个邮件任务，计数器加1
                            completedEmails.incrementAndGet();
                        } catch (MessagingException e) {
                            // 如果发送邮件时发生异常，抛出运行时异常
                            throw new RuntimeException("Sending email to " + email + " failed", e);
                        }
                    });
                } catch (Exception e) {
                    // 如果邮件发送失败，记录状态为 false，并打印错误信息
                    sendStatus.put(email, false);
                    System.err.println("Email sending failed after " + MAX_RETRIES + " attempts for recipient: " + email + " - " + e.getMessage());
                }
            }

            // 等待所有邮件发送任务完成
            while (completedEmails.get() < to.size()) {
                Thread.sleep(RETRY_INTERVAL); // 休眠一个重试间隔时间
            }

            // 发送完成后关闭 Transport
            if (transport.isConnected()) {
                transport.close();
            }
        } catch (Exception e) {
            // 如果在发送过程中发生异常，打印异常信息
            e.printStackTrace();
        }

        // 返回邮件发送状态的统计信息
        return sendStatus;
    }

    @Override
    public boolean sendEmailWithTemplate(String to, String subject, String templatePath, Map<String, String> templateParams, String filePath) throws MessagingException, IOException, TemplateException, URISyntaxException {
        // 加载模板内容
        String templateContent;
        try {
            templateContent = loadTemplateContent(templatePath, templateParams);
        } catch(Exception e){
            System.err.println("Loading template + " + templatePath + " failed" +  " - " +  e.getMessage());
            return false;
        }

        boolean result = sendEmail(to, subject, templateContent, filePath, true);

        // 调用 sendEmail 方法发送邮件
        return result;
    }

    private String loadTemplateContent(String templatePath, Map<String, String> templateParams) throws IOException, TemplateException, URISyntaxException {
        // 配置 FreeMarker
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_34);

        // 获取 templates 文件夹的路径
        URL templateUrl = getClass().getClassLoader().getResource(templateDir);
        if (templateUrl == null) {
            throw new IllegalArgumentException("Templates directory not found: " + templateDir);
        }

        // 将 URL 转换为 File 对象
        File templatesDir = Paths.get(templateUrl.toURI()).toFile();

        // 设置模板加载路径
        cfg.setDirectoryForTemplateLoading(templatesDir);
        cfg.setDefaultEncoding("UTF-8");

        // 加载模板
        Template template = cfg.getTemplate(templatePath);

        // 使用模板和参数生成最终内容
        StringWriter writer = new StringWriter();
        template.process(templateParams, writer);
        return writer.toString();
    }

    public CompletableFuture<Boolean> sendEmailAsync(String to, String subject, String body, String filePath, boolean isHtml) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 调用 sendEmail 方法发送邮件
                return sendEmail(to, subject, body, filePath, isHtml);
            } catch (Exception e) {
                // 异步任务中捕获异常并打印日志
                e.printStackTrace();
                return false; // 返回失败结果
            }
        }, executor);  // 指定使用自定义线程池
    }
}