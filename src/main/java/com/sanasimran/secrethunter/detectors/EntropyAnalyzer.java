package com.sanasimran.secrethunter.detectors;

import com.sanasimran.secrethunter.model.SecretMatch;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EntropyAnalyzer {

    // Candidate strings: quoted values or standalone tokens of decent length
    private static final Pattern CANDIDATE_PATTERN =
            Pattern.compile("['\"]([A-Za-z0-9+/=_\\-]{20,100})['\"]");

    private static final double ENTROPY_THRESHOLD = 4.3; // tuned for base64/hex-like secrets
    private static final int MIN_LENGTH = 20;

    public List<SecretMatch> scan(String content) {
        List<SecretMatch> matches = new ArrayList<>();
        Matcher matcher = CANDIDATE_PATTERN.matcher(content);

        while (matcher.find()) {
            String candidate = matcher.group(1);
            if (candidate.length() < MIN_LENGTH) continue;

            double entropy = calculateShannonEntropy(candidate);

            if (entropy >= ENTROPY_THRESHOLD && !isLikelyFalsePositive(candidate)) {
                matches.add(new SecretMatch(
                        "High-Entropy String",
                        candidate,
                        "Medium",
                        "Entropy (" + String.format("%.2f", entropy) + " bits)",
                        matcher.start()
                ));
            }
        }
        return matches;
    }

    private double calculateShannonEntropy(String input) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : input.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }

        double entropy = 0.0;
        int length = input.length();

        for (int count : freq.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    // Filter out common false positives: UUIDs with obvious patterns, repeated chars, hex-only hashes etc.
    private boolean isLikelyFalsePositive(String candidate) {
        // Reject if it's all lowercase hex (common hash, less likely to be a "secret" value per se)
        if (candidate.matches("[0-9a-f]{20,}")) return false; // keep hashes flagged low priority actually - allow through
        // Reject if too repetitive (low unique char ratio despite passing entropy)
        long uniqueChars = candidate.chars().distinct().count();
        return uniqueChars < 6; // true = false positive, filtered out
    }
}