package org.openidentity.conformance;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.MlDsa65Key;
import org.openidentity.crypto.Ed25519;
import org.openidentity.crypto.MlDsa65;
import org.openidentity.crypto.SigningInputs;
import org.openidentity.core.Ed25519Key;

class CryptoV01ConformanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final String BASE = "/openidentity-v0.1.1/";

    @Test
    void cryptographicAgilityResourceMatchesPublishedChecksum() throws Exception {
        byte[] bytes = resource("cryptographic-agility-v0.1.json");
        String expected = new String(resource("cryptographic-agility-v0.1.sha256"), StandardCharsets.UTF_8)
                .trim().split("\\s+")[0];
        assertEquals(expected, HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
    }

    @Test
    void v02HybridCreateSignaturesVerify() throws Exception {
        JsonNode v = vector("V02");
        byte[] operation = hex(v, "operationBytesHex");
        byte[] signingInput = hex(v, "signingInputHex");
        assertArrayEquals(signingInput, SigningInputs.operation(operation));
        assertTrue(Ed25519.verify(
                Ed25519Key.of(hex(v, "ed25519PublicKeyHex")),
                signingInput, hex(v, "ed25519SignatureHex")));
        assertTrue(MlDsa65.verify(
                MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex")),
                signingInput, hex(v, "mlDsa65SignatureHex")));
        assertEquals(1952, hex(v, "mlDsa65PublicKeyHex").length);
        assertEquals(3309, hex(v, "mlDsa65SignatureHex").length);
    }

    private static JsonNode vector(String id) throws Exception {
        JsonNode root = JSON.readTree(resource("cryptographic-agility-v0.1.json"));
        for (JsonNode v : root.path("valid")) if (id.equals(v.path("id").asText())) return v;
        throw new AssertionError("Missing vector " + id);
    }
    private static byte[] hex(JsonNode node, String field) { return HEX.parseHex(node.path(field).asText()); }
    private static byte[] resource(String name) throws Exception {
        try (InputStream in = CryptoV01ConformanceTest.class.getResourceAsStream(BASE + name)) {
            if (in == null) throw new AssertionError("Missing resource " + name);
            return in.readAllBytes();
        }
    }
}
