package org.tool.passfort.util.http;

import org.tool.passfort.model.ClientDeviceInfo;
import ua_parser.Client;
import ua_parser.Parser;

public class UserAgentUtil {
    private static final Parser parser = new Parser();

    public static ClientDeviceInfo parseUserAgent(String userAgent) {
        // 解析用户代理字符串
        Client client = parser.parse(userAgent);

        String deviceType = "", osName = "", osVersion = "", browserName = "", browserVersion = "";

        // 提取解析结果
        if(client.device.family != null) deviceType = client.device.family;
        if(client.os.family != null) osName = client.os.family;
        if(client.os.major != null && client.os.minor != null && client.os.patch != null) osVersion = client.os.major + "." + client.os.minor + "." + client.os.patch;
        if(client.userAgent.family != null) browserName = client.userAgent.family;
        if(client.userAgent.major != null && client.userAgent.minor != null && client.userAgent.patch != null) browserVersion = client.userAgent.major + "." + client.userAgent.minor + "." + client.userAgent.patch;

        return new ClientDeviceInfo("", deviceType, osName, osVersion, browserName, browserVersion);
    }
}
