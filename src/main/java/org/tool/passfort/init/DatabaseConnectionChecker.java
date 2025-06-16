package org.tool.passfort.init;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

@Component
@Order(1)
public class DatabaseConnectionChecker implements ApplicationRunner {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseConnectionChecker.class);

    private DataSource dataSource;

    @Autowired
    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void run(ApplicationArguments args) {
        // 检查数据库连接
        try (Connection connection = dataSource.getConnection()) {
            if (connection.isValid(2)) { // 检查连接是否有效，超时时间为2秒
                logger.info("Connected to database successfully.");
            } else {
                throw new RuntimeException("Database connection is not valid.");
            }
        } catch (SQLException e) {
            String errorMessage = e.getMessage();
            String detailedMessage = analyzeDatabaseError(errorMessage);
            logger.error("Failed to connect to database: {}", detailedMessage);
        }
    }

    private String analyzeDatabaseError(String errorMessage) {
        if (errorMessage.contains("Access denied for user")) {
            return "Authentication failed: Check your username and password.";
        } else if (errorMessage.contains("SSL connection error") || errorMessage.contains("SSLHandshakeException")) {
            return "SSL connection error: Check your SSL certificate and configuration.";
        } else if (errorMessage.contains("Unknown database")) {
            return "Database does not exist: Check the database name.";
        } else if (errorMessage.contains("Connection refused") || errorMessage.contains("Could not create connection")) {
            return "Connection refused: Check the database host and port.";
        } else if (errorMessage.contains("PKIX path building failed")) {
            return "SSL certificate validation failed: Check the trust store and certificates.";
        } else {
            return "Unknown error: " + errorMessage;
        }
    }
}
