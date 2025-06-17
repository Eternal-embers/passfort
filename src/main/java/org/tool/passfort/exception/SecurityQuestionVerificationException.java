package org.tool.passfort.exception;

public class SecurityQuestionVerificationException extends Exception{
    private final int errorQuestionIndex;

    public SecurityQuestionVerificationException(String message, int errorQuestionIndex) {
        super(message);
        this.errorQuestionIndex = errorQuestionIndex;
    }

    public int getErrorQuestionIndex() {
        return errorQuestionIndex;
    }
}
