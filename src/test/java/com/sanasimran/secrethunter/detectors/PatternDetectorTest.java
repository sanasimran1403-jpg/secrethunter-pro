package com.sanasimran.secrethunter.detectors;

import com.sanasimran.secrethunter.model.SecretMatch;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PatternDetectorTest {

    private final PatternDetector detector = new PatternDetector();

    @Test
    void detectsAwsAccessKey() {
        String content = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.stream().anyMatch(m -> m.getType().equals("AWS Access Key")));
    }

    @Test
    void detectsStripeKey() {
        String content = "api_key: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.stream().anyMatch(m -> m.getType().equals("Stripe API Key")));
    }

    @Test
    void detectsJwtToken() {
        String content = "token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N\"";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.stream().anyMatch(m -> m.getType().equals("JWT Token")));
    }

    @Test
    void detectsInternalIpAddress() {
        String content = "server = \"192.168.1.100\"";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.stream().anyMatch(m -> m.getType().equals("Internal IP Address")));
    }

    @Test
    void detectsHardcodedPassword() {
        String content = "password: \"SuperSecret123!\"";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.stream().anyMatch(m -> m.getType().equals("Hardcoded Password")));
    }

    @Test
    void doesNotFlagCleanContent() {
        String content = "<html><body><h1>Hello World</h1><p>This is a clean page with no secrets.</p></body></html>";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.isEmpty(), "Clean content should not produce any findings");
    }

    @Test
    void detectsMultipleSecretsInSameContent() {
        String content = "aws_key=\"AKIAIOSFODNN7EXAMPLE\" password=\"MySecret99!\"";
        List<SecretMatch> matches = detector.scan(content);

        assertTrue(matches.size() >= 2, "Should detect both AWS key and password");
    }

    @Test
    void ignoresPublicIpAddress() {
        String content = "server = \"8.8.8.8\""; // public DNS, not internal range
        List<SecretMatch> matches = detector.scan(content);

        assertFalse(matches.stream().anyMatch(m -> m.getType().equals("Internal IP Address")));
    }
}