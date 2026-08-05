package com.sanasimran.secrethunter.detectors;

import com.sanasimran.secrethunter.config.CustomPatternStore;
import com.sanasimran.secrethunter.model.SecretMatch;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class PatternDetector {

    private static final Map<String, String[]> PATTERNS = new LinkedHashMap<>();

    static {
        PATTERNS.put("AWS Access Key", new String[]{"AKIA[0-9A-Z]{16}", "High"});
        PATTERNS.put("AWS Secret Key", new String[]{"(?i)aws_secret_access_key['\"]?\\s*[:=]\\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "High"});
        PATTERNS.put("GitHub Token", new String[]{"gh[pousr]_[A-Za-z0-9]{36}", "High"});
        PATTERNS.put("Google API Key", new String[]{"AIza[0-9A-Za-z\\-_]{35}", "High"});
        PATTERNS.put("Stripe API Key", new String[]{"sk_live_[0-9a-zA-Z]{24,}", "High"});
        PATTERNS.put("Slack Token", new String[]{"xox[baprs]-[0-9a-zA-Z-]{10,}", "High"});
        PATTERNS.put("JWT Token", new String[]{"eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*", "Medium"});
        PATTERNS.put("Private Key Header", new String[]{"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "High"});
        PATTERNS.put("Generic API Key", new String[]{"(?i)(api[_-]?key|apikey)['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{16,45}['\"]", "Medium"});
        PATTERNS.put("Internal IP Address", new String[]{"\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b", "Low"});
        PATTERNS.put("Hardcoded Password", new String[]{"(?i)(password|passwd|pwd)['\"]?\\s*[:=]\\s*['\"][^'\"\\s]{6,}['\"]", "Medium"});
    }

    public List<SecretMatch> scan(String content) {
        List<SecretMatch> matches = new ArrayList<>();

        for (Map.Entry<String, String[]> entry : PATTERNS.entrySet()) {
            String type = entry.getKey();
            String regex = entry.getValue()[0];
            String severity = entry.getValue()[1];

            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(content);

            while (matcher.find()) {
                matches.add(new SecretMatch(type, matcher.group(), severity, "Regex", matcher.start()));
            }
        }

        // Scan using user-defined custom patterns
        for (CustomPatternStore.CustomPattern cp : CustomPatternStore.getAll()) {
            try {
                Pattern pattern = Pattern.compile(cp.regex);
                Matcher matcher = pattern.matcher(content);
                while (matcher.find()) {
                    matches.add(new SecretMatch(cp.name, matcher.group(), cp.severity, "Custom Regex", matcher.start()));
                }
            } catch (PatternSyntaxException ignored) {
                // Invalid regex from user - skip silently, UI validates on add anyway
            }
        }

        return matches;
    }
}