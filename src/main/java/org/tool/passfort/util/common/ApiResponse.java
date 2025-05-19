package org.tool.passfort.util.common;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ApiResponse<T> {
    // Getter和Setter方法
    private int code; // 状态码
    private String msg; // 消息
    private T data; // 返回的数据

    // 构造方法
    public ApiResponse() {
        this.code = 200; // 默认成功状态码
        this.msg = "操作成功";
    }

    public ApiResponse(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public ApiResponse(int code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    // 静态方法，方便创建成功和失败的响应
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(200, "操作成功", data);
    }

    public static <T> ApiResponse<T> failure(int code, String msg) {
        return new ApiResponse<>(code, msg);
    }
}
