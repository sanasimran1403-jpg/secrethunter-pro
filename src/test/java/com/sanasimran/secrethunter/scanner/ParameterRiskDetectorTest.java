package com.sanasimran.secrethunter.scanner;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class ParameterRiskDetectorTest {

    private final ParameterRiskDetector detector = new ParameterRiskDetector();

    private ParsedHttpParameter mockParam(String name, String value) {
        ParsedHttpParameter param = Mockito.mock(ParsedHttpParameter.class);
        when(param.name()).thenReturn(name);
        when(param.value()).thenReturn(value);
        return param;
    }

    @Test
    void flagsNumericUserIdAsIdor() {
        List<ParsedHttpParameter> params = List.of(mockParam("user_id", "123"));
        List<ParameterRiskDetector.ParamRisk> risks = detector.analyze(params);

        assertTrue(risks.stream().anyMatch(r -> r.type == ParameterRiskDetector.RiskType.IDOR));
    }

    @Test
    void doesNotFlagNonNumericUserId() {
        List<ParsedHttpParameter> params = List.of(mockParam("user_id", "abc-uuid-string"));
        List<ParameterRiskDetector.ParamRisk> risks = detector.analyze(params);

        assertFalse(risks.stream().anyMatch(r -> r.type == ParameterRiskDetector.RiskType.IDOR));
    }

    @Test
    void flagsRedirectParamAsSsrf() {
        List<ParsedHttpParameter> params = List.of(mockParam("redirect", "http://evil.com"));
        List<ParameterRiskDetector.ParamRisk> risks = detector.analyze(params);

        assertTrue(risks.stream().anyMatch(r -> r.type == ParameterRiskDetector.RiskType.SSRF));
    }

    @Test
    void doesNotFlagUnrelatedParam() {
        List<ParsedHttpParameter> params = List.of(mockParam("page", "2"));
        List<ParameterRiskDetector.ParamRisk> risks = detector.analyze(params);

        assertTrue(risks.isEmpty());
    }

    @Test
    void flagsUrlLikeValueEvenWithGenericName() {
        List<ParsedHttpParameter> params = List.of(mockParam("data", "http://internal-service.local/api"));
        List<ParameterRiskDetector.ParamRisk> risks = detector.analyze(params);

        assertTrue(risks.stream().anyMatch(r -> r.type == ParameterRiskDetector.RiskType.SSRF));
    }
}