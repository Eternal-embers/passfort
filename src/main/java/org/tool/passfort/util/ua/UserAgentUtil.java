package org.tool.passfort.util.ua;

import org.tool.passfort.model.ClientDeviceInfo;
import ua_parser.Client;
import ua_parser.Parser;

public class UserAgentUtil {
    private static final Parser parser = new Parser();

    public static ClientDeviceInfo parseUserAgent(String userAgent) {
        // 解析用户代理字符串
        Client client = parser.parse(userAgent);

        // 提取解析结果
        String deviceType = client.device.family;
        String osName = client.os.family;
        String osVersion = client.os.major + "." + client.os.minor + "." + client.os.patch;
        String browserName = client.userAgent.family;
        String browserVersion = client.userAgent.major + "." + client.userAgent.minor + "." + client.userAgent.patch;

        return new ClientDeviceInfo(deviceType, osName, osVersion, browserName, browserVersion);
    }
}
