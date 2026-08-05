package com.sanasimran.secrethunter.model;

public class SecretMatch {
    private final String type;         // e.g., "AWS Access Key"
    private final String value;        // the matched secret (masked for display)
    private final String severity;     // High / Medium / Low
    private final String detectionMethod; // "Regex" or "Entropy"
    private final int offset;          // position in response body

    public SecretMatch(String type, String value, String severity, String detectionMethod, int offset) {
        this.type = type;
        this.value = value;
        this.severity = severity;
        this.detectionMethod = detectionMethod;
        this.offset = offset;
    }

    public String getType() { return type; }
    public String getValue() { return value; }
    public String getSeverity() { return severity; }
    public String getDetectionMethod() { return detectionMethod; }
    public int getOffset() { return offset; }

    // Mask secret for safe display (show first 4 + last 4 chars only)
    public String getMaskedValue() {
        if (value.length() <= 10) return "****";
        return value.substring(0, 4) + "..." + value.substring(value.length() - 4);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s (%s) - %s", severity, type, detectionMethod, getMaskedValue());
    }
}