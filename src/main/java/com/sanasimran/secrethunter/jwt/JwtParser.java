package com.sanasimran.secrethunter.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JwtParser {

    public static class DecodedJwt {
        public final String header;
        public final String payload;
        public final String signature;
        public final String rawToken;

        public DecodedJwt(String header, String payload, String signature, String rawToken) {
            this.header = header;
            this.payload = payload;
            this.signature = signature;
            this.rawToken = rawToken;
        }
    }

    public static DecodedJwt decode(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;

        try {
            String header = decodeBase64Url(parts[0]);
            String payload = decodeBase64Url(parts[1]);
            String signature = parts.length > 2 ? parts[2] : "";
            return new DecodedJwt(header, payload, signature, token);
        } catch (Exception e) {
            return null;
        }
    }

    private static String decodeBase64Url(String input) {
        byte[] decoded = Base64.getUrlDecoder().decode(padBase64(input));
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static String padBase64(String input) {
        int padding = input.length() % 4;
        if (padding == 2) return input + "==";
        if (padding == 3) return input + "=";
        return input;
    }
}