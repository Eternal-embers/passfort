package org.tool.passfort.util.http;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CookieUtil {
    /**
     * 创建 Https Only Cookie
     * @param name cookie名称
     * @param value cookie值
     * @param maxAge 有效期（秒）
     * @param path cookie路径，即path所在的url都会携带此Cookie，以客户端的url为准
     * @return 返回创建的Cookie
     */
    public static Cookie createCookie(String name, String value, int maxAge, String path){
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true); // 设置为 HttpOnly，防止通过 JavaScript 访问
        cookie.setSecure(true); // 设置为 Secure，仅在 HTTPS 连接中传输
        cookie.setMaxAge(maxAge); // 设置有效期
        cookie.setPath(path); // 设置路径

        return cookie;
    }

    /**
     * 获取 cookie 的值
     * @param request 请求对象
     * @param cookieName cookie 名称
     * @return 返回 cookie 的值
     */
    public static String getCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * 删除身份验证的 cookie
     */
    public static void deleteCookie(HttpServletResponse response, String cookieName, String path) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0); // 设置Cookie的过期时间为0，表示立即过期
        cookie.setPath(path); // 设置Cookie的作用路径，必须与设置Cookie时的路径一致

        response.addCookie(cookie);  // 将修改后的Cookie添加到响应中
    }
}
