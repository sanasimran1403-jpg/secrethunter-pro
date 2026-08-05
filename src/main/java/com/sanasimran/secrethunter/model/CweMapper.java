package com.sanasimran.secrethunter.model;

import java.util.HashMap;
import java.util.Map;

public class CweMapper {

    private static final Map<String, String> CWE_MAP = new HashMap<>();

    static {
        CWE_MAP.put("AWS Access Key", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("AWS Secret Key", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("GitHub Token", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("Google API Key", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("Stripe API Key", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("Slack Token", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("JWT Token", "CWE-522: Insufficiently Protected Credentials");
        CWE_MAP.put("Private Key Header", "CWE-321: Use of Hard-coded Cryptographic Key");
        CWE_MAP.put("Generic API Key", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("Internal IP Address", "CWE-200: Exposure of Sensitive Information");
        CWE_MAP.put("Hardcoded Password", "CWE-259: Use of Hard-coded Password");
        CWE_MAP.put("High-Entropy String", "CWE-798: Use of Hard-coded Credentials");
        CWE_MAP.put("IDOR-prone Parameter", "CWE-639: Authorization Bypass Through User-Controlled Key");
        CWE_MAP.put("SSRF-prone Parameter", "CWE-918: Server-Side Request Forgery (SSRF)");
    }

    public static String getCwe(String findingType) {
        return CWE_MAP.getOrDefault(findingType, "CWE-200: Exposure of Sensitive Information");
    }
}