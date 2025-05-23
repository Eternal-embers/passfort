package org.tool.passfort.service;

public interface ApplicationInfoService {
    String getOsInfo();

    String getCpuInfo();

    String getDatabaseVersion();

    String getRedisVersion();
}
