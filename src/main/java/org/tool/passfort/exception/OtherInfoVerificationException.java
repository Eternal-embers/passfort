package org.tool.passfort.exception;

public class OtherInfoVerificationException extends Exception{
    private final String errorParam;

    public OtherInfoVerificationException(String message, String errorParam) {
        super(message);
        this.errorParam = errorParam;
    }

    public String getErrorParam() {
        return errorParam;
    }
}
