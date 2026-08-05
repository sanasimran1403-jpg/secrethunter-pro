package com.sanasimran.secrethunter.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.sanasimran.secrethunter.detectors.EntropyAnalyzer;
import com.sanasimran.secrethunter.detectors.PatternDetector;
import com.sanasimran.secrethunter.model.SecretMatch;
import com.sanasimran.secrethunter.ui.SecretHunterTab;

import java.util.ArrayList;
import java.util.List;

public class PassiveSecretScanner implements HttpHandler {

    private final MontoyaApi api;
    private final PatternDetector patternDetector;
    private final EntropyAnalyzer entropyAnalyzer;
    private final ParameterRiskDetector paramRiskDetector;
    private final SecretHunterTab tab;

    public PassiveSecretScanner(MontoyaApi api, SecretHunterTab tab) {
        this.api = api;
        this.tab = tab;
        this.patternDetector = new PatternDetector();
        this.entropyAnalyzer = new EntropyAnalyzer();
        this.paramRiskDetector = new ParameterRiskDetector();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            List<ParsedHttpParameter> params = requestToBeSent.parameters();
            List<ParameterRiskDetector.ParamRisk> risks = paramRiskDetector.analyze(params);

            if (!risks.isEmpty()) {
                String url = requestToBeSent.url();
                List<SecretMatch> matches = new ArrayList<>();

                for (ParameterRiskDetector.ParamRisk risk : risks) {
                    String type = risk.type == ParameterRiskDetector.RiskType.IDOR
                            ? "IDOR-prone Parameter"
                            : "SSRF-prone Parameter";
                    String severity = risk.type == ParameterRiskDetector.RiskType.SSRF ? "High" : "Medium";
                    String value = risk.paramName + " = " + risk.paramValue;

                    matches.add(new SecretMatch(type, value, severity, "Param Analysis", 0));
                }

                logFindings(url, matches);
                for (SecretMatch match : matches) {
                    tab.addFinding(url, match);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[SecretHunter] Error analyzing request params: " + e.getMessage());
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            HttpResponse response = responseReceived;
            String body = response.bodyToString();

            if (body == null || body.isEmpty()) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            List<SecretMatch> findings = new ArrayList<>();
            findings.addAll(patternDetector.scan(body));
            findings.addAll(entropyAnalyzer.scan(body));

            if (!findings.isEmpty()) {
                String url = responseReceived.initiatingRequest().url();
                logFindings(url, findings);

                for (SecretMatch match : findings) {
                    tab.addFinding(url, match);
                }
            }

        } catch (Exception e) {
            api.logging().logToError("[SecretHunter] Error scanning response: " + e.getMessage());
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void logFindings(String url, List<SecretMatch> findings) {
        api.logging().logToOutput("========================================");
        api.logging().logToOutput("[SecretHunter] Findings in: " + url);
        for (SecretMatch match : findings) {
            api.logging().logToOutput("  " + match.toString());
        }
        api.logging().logToOutput("========================================");
    }
}