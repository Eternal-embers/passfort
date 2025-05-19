package org.tool.passfort.exception;

public class DatabaseOperationException extends Exception {
    public DatabaseOperationException(String email, String message) {
        super("Database operation failed for email: " + email + ". " + message);
    }
}
