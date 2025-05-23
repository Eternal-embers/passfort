package org.tool.passfort.init;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.tool.passfort.service.ApplicationInfoService;
import org.tool.passfort.service.impl.EmailServiceImpl;

import java.util.HashMap;
import java.util.Map;

@Component
@Order(2)
public class MailServiceChecker implements ApplicationRunner {
    private static final Logger logger = LoggerFactory.getLogger(MailServiceChecker.class);
    private final EmailServiceImpl emailService;
    private final ApplicationInfoService appInfo;

    @Value("${spring.mail.username}")
    private String to;

    @Autowired
    public MailServiceChecker(EmailServiceImpl emailService, ApplicationInfoService appInfo) {
        this.emailService = emailService;
        this.appInfo = appInfo;
    }

    @Override
    public void run(ApplicationArguments args) {
        Map<String, String>  templateVariables = new HashMap<>();

        templateVariables.put("osInfo", appInfo.getOsInfo());
        templateVariables.put("cpuInfo", appInfo.getCpuInfo());
        templateVariables.put("databaseVersion", appInfo.getDatabaseVersion());
        templateVariables.put("redisVersion", appInfo.getRedisVersion());

        try {
            emailService.sendEmailWithTemplate(to, "PassFort 邮件服务检测", "app.html", templateVariables);
            logger.info("Email service is running normally.");//邮件服务正常运行
        } catch (Exception e) {
            logger.error("Email service is not available: {} - {} - {}", e.getClass().getName(), e.getMessage(), e.getStackTrace()[0].toString());//邮件服务不可用
        }
    }
}
