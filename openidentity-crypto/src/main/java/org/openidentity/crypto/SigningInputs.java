package org.openidentity.crypto;

import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.VerificationMethodId;

public final class SigningInputs {
    public static final int VERSION = 1;
    private SigningInputs() {}

    public static byte[] operation(byte[] operationBytes) {
        Objects.requireNonNull(operationBytes, "operationBytes");
        return OpenIdentityCborEncoder.encodeOperationSigningInput(
                SigningDomain.OPERATION.value(), VERSION, operationBytes);
    }

    public static byte[] controllerProof(byte[] operationBytes, VerificationMethodId methodId) {
        Objects.requireNonNull(operationBytes, "operationBytes");
        Objects.requireNonNull(methodId, "methodId");
        return OpenIdentityCborEncoder.encodeMethodSigningInput(
                SigningDomain.CONTROLLER_PROOF.value(), VERSION, operationBytes, methodId.bytes());
    }

    public static byte[] recovery(byte[] operationBytes, VerificationMethodId methodId) {
        Objects.requireNonNull(operationBytes, "operationBytes");
        Objects.requireNonNull(methodId, "methodId");
        return OpenIdentityCborEncoder.encodeMethodSigningInput(
                SigningDomain.RECOVERY.value(), VERSION, operationBytes, methodId.bytes());
    }
}
