package org.tool.passfort.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.tool.passfort.service.ApplicationInfoService;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Controller
public class IndexController {
    private final ApplicationInfoService appInfo;

    @Autowired
    public IndexController(ApplicationInfoService applicationInfoService) {
        this.appInfo = applicationInfoService;
    }

    @GetMapping("/")
    public String index(Model model) {
        // 软件信息
        model.addAttribute("projectName", "passfort");
        model.addAttribute("version", "v1.0.0");
        model.addAttribute("buildTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        model.addAttribute("developerInfo", "lqw");
        model.addAttribute("copyright", "lqw 版权所有 © 2025");
        model.addAttribute("docsLink", "https://github.com/Eternal-embers/passfort");
        model.addAttribute("supportInfo", "https://github.com/Eternal-embers/passfort");

        // 系统信息
        model.addAttribute("osInfo", appInfo.getOsInfo());
        model.addAttribute("javaVersion", System.getProperty("java.version"));
        try {
            model.addAttribute("serverInfo", InetAddress.getLocalHost().getHostName() + " (" + InetAddress.getLocalHost().getHostAddress() + ")");
        } catch (UnknownHostException e) {
            model.addAttribute("serverInfo", "未知服务器");
        }
        model.addAttribute("memoryInfo", Runtime.getRuntime().totalMemory() / (1024 * 1024) + "MB / " + Runtime.getRuntime().maxMemory() / (1024 * 1024) + "MB");
        model.addAttribute("cpuInfo", appInfo.getCpuInfo());
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        model.addAttribute("uptime", formatUptime(runtimeMXBean.getUptime()));
        model.addAttribute("dbVersion", appInfo.getDatabaseVersion());
        model.addAttribute("redisVersion", appInfo.getRedisVersion());

        return "index";
    }

    private String formatUptime(long uptime) {
        long days = uptime / (24 * 60 * 60 * 1000);
        long hours = (uptime / (60 * 60 * 1000)) % 24;
        long minutes = (uptime / (60 * 1000)) % 60;
        long seconds = (uptime / 1000) % 60;
        return days + "天 " + hours + "小时 " + minutes + "分钟 " + seconds + "秒";
    }
}