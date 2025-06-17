package org.tool.passfort.exception;

public class PersonalInfoVerificationException extends Exception{
    private String errorParam;

    public PersonalInfoVerificationException(String message, String errorParam){
        super(message);
        this.errorParam = errorParam;
    }

    public String getErrorParam() {
        return errorParam;
    }
}
