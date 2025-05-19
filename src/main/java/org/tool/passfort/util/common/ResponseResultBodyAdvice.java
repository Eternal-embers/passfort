package org.tool.passfort.util.common;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.lang.annotation.Annotation;

@RestControllerAdvice
public class ResponseResultBodyAdvice implements ResponseBodyAdvice<Object> {
    // @ResponseResult 注解的类型。
    private static final Class<? extends Annotation> ANNOTATION_TYPE = ResponseResult.class;

    // 用于判断是否需要对某个控制器方法的返回值进行处理。
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        // 检查控制器类是否被标记了 @ResponseResult 或 控制器方法是否被标记了 @ResponseResult
        return AnnotatedElementUtils.hasAnnotation(returnType.getContainingClass(), ANNOTATION_TYPE) || returnType.hasMethodAnnotation(ANNOTATION_TYPE);
    }

    // 在返回值被写入 HTTP 响应体之前对其进行处理。
    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        if (body instanceof ApiResponse) {
            return body; // 如果已经是ApiResponse类型，直接返回
        }
        return ApiResponse.success(body); // 将返回值包装为ApiResponse
    }
}
