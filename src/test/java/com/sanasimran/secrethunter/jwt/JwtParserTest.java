package com.sanasimran.secrethunter.jwt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtParserTest {

    private static final String SAMPLE_JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    @Test
    void decodesValidJwt() {
        JwtParser.DecodedJwt decoded = JwtParser.decode(SAMPLE_JWT);

        assertNotNull(decoded);
        assertTrue(decoded.header.contains("HS256"));
        assertTrue(decoded.payload.contains("John Doe"));
    }

    @Test
    void returnsNullForInvalidToken() {
        JwtParser.DecodedJwt decoded = JwtParser.decode("not-a-valid-jwt");
        assertNull(decoded);
    }

    @Test
    void extractsSignatureCorrectly() {
        JwtParser.DecodedJwt decoded = JwtParser.decode(SAMPLE_JWT);
        assertEquals("dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", decoded.signature);
    }
}