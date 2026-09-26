package org.openidentity.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.openidentity.cbor.DeterministicCbor;
import org.openidentity.core.VerificationMethodId;

public final class SigningInputs {
    public static final int VERSION = 1;
    private SigningInputs() {}

    public static byte[] operation(byte[] operationBytes) {
        return encode(SigningDomain.OPERATION, operationBytes, null);
    }

    public static byte[] controllerProof(byte[] operationBytes, VerificationMethodId methodId) {
        Objects.requireNonNull(methodId, "methodId");
        return encode(SigningDomain.CONTROLLER_PROOF, operationBytes, methodId.bytes());
    }

    public static byte[] recovery(byte[] operationBytes, VerificationMethodId methodId) {
        Objects.requireNonNull(methodId, "methodId");
        return encode(SigningDomain.RECOVERY, operationBytes, methodId.bytes());
    }

    private static byte[] encode(SigningDomain domain, byte[] operationBytes, byte[] methodId) {
        Objects.requireNonNull(domain, "domain");
        Objects.requireNonNull(operationBytes, "operationBytes");
        DeterministicCbor c = new DeterministicCbor();
        c.array(methodId == null ? 3 : 4);
        c.text(domain.value());
        c.integer(VERSION);
        c.bytes(operationBytes);
        if (methodId != null) c.bytes(methodId);
        return c.toByteArray();
    }
}
