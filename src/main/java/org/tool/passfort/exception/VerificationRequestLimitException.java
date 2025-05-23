package org.tool.passfort.exception;

public class VerificationRequestLimitException extends Exception{
   public VerificationRequestLimitException(String email) {
      super("Request verification code too frequently for email: " + email + ".");//请求验证码过于频繁
   }
}
