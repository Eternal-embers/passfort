package org.tool.passfort.init;

import jakarta.mail.*;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Properties;

import org.springframework.mail.javamail.JavaMailSenderImpl;

@Component
@Order(2)
public class MailServiceChecker implements ApplicationRunner {
    private static final Logger logger = LoggerFactory.getLogger(MailServiceChecker.class);

    @Value("${spring.mail.host}")
    private String mailHost;

    @Value("${spring.mail.port}")
    private int mailPort;

    @Value("${spring.mail.username}")
    private String mailUsername;

    @Value("${spring.mail.password}")
    private String mailPassword;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        logger.info("Starting mail service connectivity check...");
        long startTime = System.currentTimeMillis(); // 开始计时
        try {
            // Create a JavaMailSender instance
            Properties props = getProperties();

            // Create a session and transport
            Session session = Session.getInstance(props);
            Transport transport = session.getTransport();

            // Connect to the mail server
            transport.connect(mailHost, mailUsername, mailPassword);

            // If no exception is thrown, the connection is successful
            long endTime = System.currentTimeMillis(); // 结束计时
            long duration = endTime - startTime; // 计算耗时
            logger.info("Mail service connectivity check passed. Mail server is reachable. Connection time: {} ms.", duration);
        } catch (MessagingException e) {
            long endTime = System.currentTimeMillis(); // 结束计时（即使失败也记录耗时）
            long duration = endTime - startTime;
            logger.error("Mail service connectivity check failed. Unable to connect to mail server in {} ms. Error: {}. Please check your network connection or try changing the DNS to 8.8.8.8 or 114.114.114.114 if the problem persists.", duration, e.getMessage());
            logger.debug("Detailed error information:", e);
        }
    }

    @NotNull
    private Properties getProperties() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);
        mailSender.setUsername(mailUsername);
        mailSender.setPassword(mailPassword);

        // Set up properties for the mail session
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "false");
        return props;
    }
}
