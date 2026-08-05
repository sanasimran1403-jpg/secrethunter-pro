package com.sanasimran.secrethunter.scanner;

import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class ParameterRiskDetector {

    public enum RiskType { IDOR, SSRF }

    public static class ParamRisk {
        public final String paramName;
        public final String paramValue;
        public final RiskType type;
        public final String reason;

        public ParamRisk(String paramName, String paramValue, RiskType type, String reason) {
            this.paramName = paramName;
            this.paramValue = paramValue;
            this.type = type;
            this.reason = reason;
        }
    }

    private static final Pattern IDOR_NAME_PATTERN = Pattern.compile(
            "(?i)^(id|user_?id|account_?id|account_?no|order_?id|invoice_?id|" +
            "customer_?id|profile_?id|doc_?id|file_?id|record_?id|uid|uuid)$"
    );
    private static final Pattern NUMERIC_VALUE = Pattern.compile("^\\d{1,10}$");

    private static final Pattern SSRF_NAME_PATTERN = Pattern.compile(
            "(?i)^(url|uri|link|redirect|redirect_?uri|return_?url|callback|" +
            "webhook|fetch|src|source|target|dest|destination|path|proxy|host|" +
            "domain|endpoint|next|continue|image_?url|avatar_?url)$"
    );
    private static final Pattern URL_LIKE_VALUE = Pattern.compile(
            "(?i)^(https?://|//|[a-z0-9.-]+\\.[a-z]{2,})"
    );

    public List<ParamRisk> analyze(List<ParsedHttpParameter> parameters) {
        List<ParamRisk> risks = new ArrayList<>();

        for (ParsedHttpParameter param : parameters) {
            String name = param.name();
            String value = param.value();
            if (name == null || value == null || value.isBlank()) continue;

            if (IDOR_NAME_PATTERN.matcher(name).matches() && NUMERIC_VALUE.matcher(value).matches()) {
                risks.add(new ParamRisk(name, value, RiskType.IDOR,
                        "Parameter name suggests a direct object reference with a sequential/numeric value. " +
                        "Test by incrementing/decrementing the value to check for missing authorization checks."));
            }

            boolean nameMatches = SSRF_NAME_PATTERN.matcher(name).matches();
            boolean valueLooksLikeUrl = URL_LIKE_VALUE.matcher(value).find();
            if (nameMatches || (valueLooksLikeUrl && value.length() > 6)) {
                risks.add(new ParamRisk(name, value, RiskType.SSRF,
                        "Parameter may be used in a server-side request. Test with internal addresses " +
                        "(e.g. 127.0.0.1, 169.254.169.254, internal hostnames) or a Collaborator payload " +
                        "to check for SSRF."));
            }
        }
        return risks;
    }
}