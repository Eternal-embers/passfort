package org.tool.passfort.annotation;

import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.METHOD}) //注解可以用于方法和类
@Retention(RetentionPolicy.RUNTIME) // 在运行时保留主机信息
@Documented // 将注解信息包含在JavaDoc中
public @interface AuthRequired {}
