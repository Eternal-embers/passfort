package org.tool.passfort.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.tool.passfort.service.ApplicationInfoService;
import org.tool.passfort.util.redis.RedisUtil;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.OperatingSystem;

import javax.sql.DataSource;
import java.sql.*;

@Service
public class ApplicationInfoServiceImpl implements ApplicationInfoService {
    private final DataSource dataSource;
    private final SystemInfo systemInfo;
    private final StringRedisTemplate stringRedisTemplate;
    private final RedisUtil redisUtil;

    @Autowired
    public ApplicationInfoServiceImpl(DataSource dataSource, SystemInfo systemInfo, StringRedisTemplate stringRedisTemplate, RedisUtil redisUtil) {
        this.dataSource = dataSource;
        this.systemInfo = systemInfo;
        this.stringRedisTemplate = stringRedisTemplate;
        this.redisUtil = redisUtil;
    }

    public String getOsInfo() {
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

    public String getCpuInfo(){
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

    public String getDatabaseVersion() {
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


    public String getRedisVersion() {
        return redisUtil.getVersion();
    }
}
