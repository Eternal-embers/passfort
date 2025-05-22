package org.tool.passfort.exception;

public class MissingRequestContextException extends Exception{
    public MissingRequestContextException() {
        super("Missing request context");
    }
}
