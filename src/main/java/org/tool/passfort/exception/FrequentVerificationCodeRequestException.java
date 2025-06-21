package org.tool.passfort.exception;

public class FrequentVerificationCodeRequestException extends Exception{
    public FrequentVerificationCodeRequestException(String email, String ipAddress) {
        super("Request verification code too frequently for email: " + email + " from IP address: " + ipAddress);
    }
}