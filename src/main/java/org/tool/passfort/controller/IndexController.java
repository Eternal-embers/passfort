package org.tool.passfort.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.OperatingSystem;

import javax.sql.DataSource;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Controller
public class IndexController {
    @Autowired
    private DataSource dataSource;

    @Autowired
    SystemInfo systemInfo;

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
        model.addAttribute("osInfo", getOsInfo());
        model.addAttribute("javaVersion", System.getProperty("java.version"));
        try {
            model.addAttribute("serverInfo", InetAddress.getLocalHost().getHostName() + " (" + InetAddress.getLocalHost().getHostAddress() + ")");
        } catch (UnknownHostException e) {
            model.addAttribute("serverInfo", "未知服务器");
        }
        model.addAttribute("memoryInfo", Runtime.getRuntime().totalMemory() / (1024 * 1024) + "MB / " + Runtime.getRuntime().maxMemory() / (1024 * 1024) + "MB");
        model.addAttribute("cpuInfo", getCpuInfo());
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        model.addAttribute("uptime", formatUptime(runtimeMXBean.getUptime()));
        model.addAttribute("dbVersion", getDatabaseVersion());

        return "index";
    }

    private String formatUptime(long uptime) {
        long days = uptime / (24 * 60 * 60 * 1000);
        long hours = (uptime / (60 * 60 * 1000)) % 24;
        long minutes = (uptime / (60 * 1000)) % 60;
        long seconds = (uptime / 1000) % 60;
        return days + "天 " + hours + "小时 " + minutes + "分钟 " + seconds + "秒";
    }

    private String getOsInfo() {
        // 获取操作系统信息
        OperatingSystem os = systemInfo.getOperatingSystem();

        // 构建操作系统信息字符串
        String osInfo = String.format("%s %s (%s)",
                os.getFamily(), // 操作系统家族（如 Windows、Linux、Mac）
                os.getVersionInfo().toString(),        // 操作系统版本信息
                os.getManufacturer() // 操作系统制造商
        );

        return osInfo;
    }

    private String getCpuInfo(){
        HardwareAbstractionLayer hal = systemInfo.getHardware();
        CentralProcessor processor = hal.getProcessor();

        // 获取CPU型号
        String cpuModel = processor.getProcessorIdentifier().getName();

        // 获取物理核心数
        int cpuCores = processor.getPhysicalProcessorCount();

        // 获取逻辑处理器数（线程数）
        int cpuThreads = processor.getLogicalProcessorCount();
        // 构建 CPU 信息字符串
        String cpuInfo = String.format("%s, %d 核心, %d 线程", cpuModel, cpuCores, cpuThreads);

        return cpuInfo;
    }

    private String getDatabaseVersion() {
        String dbVersion = "未知";
        String tlsVersion = "未知";
        try (Connection connection = dataSource.getConnection()) {
            // 获取MySQL版本
            DatabaseMetaData metaData = connection.getMetaData();
            dbVersion = metaData.getDatabaseProductVersion();

            // 检查TLS连接状态和版本
            try (Statement statement = connection.createStatement()) {
                ResultSet resultSet = statement.executeQuery("SHOW STATUS LIKE 'Ssl_version';");
                if (resultSet.next()) {
                    tlsVersion = resultSet.getString("Value");
                    if (tlsVersion == null || tlsVersion.isEmpty()) {
                        tlsVersion = "未启用 TLS";
                    }
                }
            }
        } catch (SQLException e) {
            dbVersion = "无法连接到数据库";
            tlsVersion = "无法连接到数据库";
        }
        return "MySQL Ver " + dbVersion + " - " + tlsVersion;
    }
}