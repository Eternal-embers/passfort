package org.tool.passfort.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

@RestController
public class SystemInfoController {

    @GetMapping("/")
    public String getSystemInfo() {
        StringBuilder info = new StringBuilder();

        // 系统信息
        info.append("=== System Information ===\n");
        info.append("OS Name: ").append(System.getProperty("os.name")).append("\n");
        info.append("OS Version: ").append(System.getProperty("os.version")).append("\n");
        info.append("OS Architecture: ").append(System.getProperty("os.arch")).append("\n");
        info.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
        info.append("Java Home: ").append(System.getProperty("java.home")).append("\n");

        // JVM 信息
        info.append("\n=== JVM Information ===\n");
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        info.append("JVM Uptime: ").append(runtimeMXBean.getUptime()).append(" ms\n");

        ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();
        info.append("Current Thread Count: ").append(threadMXBean.getThreadCount()).append("\n");

        // CPU 和内存信息
        OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
        if (osBean instanceof com.sun.management.OperatingSystemMXBean) {
            com.sun.management.OperatingSystemMXBean sunOsBean = (com.sun.management.OperatingSystemMXBean) osBean;
            info.append("\n=== CPU and Memory Information ===\n");
            info.append("Available Processors: ").append(sunOsBean.getAvailableProcessors()).append("\n");
            info.append("System CPU Load: ").append(sunOsBean.getSystemCpuLoad() * 100).append("%\n");
            info.append("Free Physical Memory: ").append(sunOsBean.getFreePhysicalMemorySize() / (1024L * 1024L * 1024L)).append(" GB\n");
            info.append("Total Physical Memory: ").append(sunOsBean.getTotalPhysicalMemorySize() / (1024L * 1024L * 1024L)).append(" GB\n");
        }

        // MySQL 版本信息
        info.append("\n=== MySQL Information ===\n");
        try {
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/", "username", "password");
            Properties properties = connection.getClientInfo();
            info.append("MySQL Version: ").append(properties.getProperty("serverVersion")).append("\n");
            connection.close();
        } catch (SQLException e) {
            info.append("MySQL Version: ").append("Failed to connect to MySQL").append("\n");
        }

        // 磁盘使用情况
        info.append("\n=== Disk Information ===\n");
        java.io.File[] roots = java.io.File.listRoots();
        for (java.io.File root : roots) {
            info.append("Drive: ").append(root).append("\n");
            info.append("Total Space: ").append(root.getTotalSpace() / (1024L * 1024L * 1024L)).append(" GB\n");
            info.append("Free Space: ").append(root.getFreeSpace() / (1024L * 1024L * 1024L)).append(" GB\n");
            info.append("Usable Space: ").append(root.getUsableSpace() / (1024L * 1024L * 1024L)).append(" GB\n");
        }

        return info.toString();
    }
}