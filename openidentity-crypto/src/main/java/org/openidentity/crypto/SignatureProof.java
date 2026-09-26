package org.openidentity.crypto;

import java.util.Arrays;
import java.util.Objects;
import org.openidentity.core.VerificationMethodId;
import org.openidentity.cbor.OpenIdentityCborEncoder;

public final class SignatureProof {
    private final VerificationMethodId methodId;
    private final byte[] signature;

    public SignatureProof(VerificationMethodId methodId, byte[] signature) {
        this.methodId = Objects.requireNonNull(methodId, "methodId");
        this.signature = Objects.requireNonNull(signature, "signature").clone();
        if (signature.length == 0) throw new IllegalArgumentException("signature must not be empty");
    }

    public VerificationMethodId methodId() { return methodId; }
    public byte[] signature() { return signature.clone(); }
    public byte[] encode() { return OpenIdentityCborEncoder.encodeSignatureProof(methodId.bytes(), signature); }

    @Override public boolean equals(Object other) {
        return other instanceof SignatureProof p && methodId.equals(p.methodId) && Arrays.equals(signature, p.signature);
    }
    @Override public int hashCode() { return 31 * methodId.hashCode() + Arrays.hashCode(signature); }
}
