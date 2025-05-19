package org.tool.passfort.util.encrypt;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class GeneratorUtil {
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random random = new Random();

    public static String getRandomString(int length) {
        StringBuilder builder = new StringBuilder();
        while (builder.length() < length) {
            int randomChar = random.nextInt(ALPHA_NUMERIC_STRING.length());
            char ch = ALPHA_NUMERIC_STRING.charAt(randomChar);
            builder.append(ch);
        }
        return builder.toString();
    }

    public static String getRandomNumeric(int length) {
        StringBuilder builder = new StringBuilder();
        while (builder.length() < length) {
            int randomNumeric = random.nextInt(10);
            builder.append(randomNumeric);
        }
        return builder.toString();
    }
}