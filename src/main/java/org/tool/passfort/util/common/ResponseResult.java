package org.tool.passfort.util.common;

import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.METHOD}) //@ResponseResult 注解可以被应用到控制器类或控制器方法上。
@Retention(RetentionPolicy.RUNTIME)//@ResponseResult 注解在运行时可以通过反射检查，可以在运行时判断某个控制器类或方法是否被标记了该注解。
@Documented //注解应该被包含在 JavaDoc 文档中
public @interface ResponseResult {
}
