package org.openidentity.cbor;

import org.openidentity.core.*;

public final class OpenIdentityCborEncoder {
    private OpenIdentityCborEncoder() {}

    public static byte[] encodeState(IdentityStateV1 state) {
        DeterministicCbor c = new DeterministicCbor();
        c.map(state.recoveryCommitment() == null ? 5 : 6);
        c.integer(1); c.integer(1);
        c.integer(2); c.bytes(state.identity().bytes());
        c.integer(3); c.unsigned(state.sequence().value());
        c.integer(4); c.integer(state.status().code());
        c.integer(5); encodePolicy(c, state.controllerPolicy());
        if (state.recoveryCommitment() != null) { c.integer(6); c.bytes(state.recoveryCommitment().bytes()); }
        return c.toByteArray();
    }

    public static byte[] encodeControllerPolicy(ControllerPolicy policy) { DeterministicCbor c = new DeterministicCbor(); encodePolicy(c, policy); return c.toByteArray(); }\n\n    public static byte[] encodeVerificationMethod(VerificationMethod method) { DeterministicCbor c = new DeterministicCbor(); encodeMethod(c, method); return c.toByteArray(); }\n\n    private static void encodePolicy(DeterministicCbor c, AuthorityPolicy policy) {
        if (policy.isSingle()) {
            c.map(2); c.integer(1); c.integer(1); c.integer(2); c.array(1); encodeMethod(c, policy.methods().getFirst());
        } else {
            c.map(3); c.integer(1); c.integer(2); c.integer(2); c.integer(policy.threshold());
            c.integer(3); c.array(policy.methods().size());
            for (VerificationMethod method : policy.methods()) encodeMethod(c, method);
        }
    }

    private static void encodeMethod(DeterministicCbor c, VerificationMethod method) {
        c.map(2); c.integer(1); c.bytes(method.id().bytes()); c.integer(2);
        CoseKey material = method.key();
        if (material instanceof Ed25519Key ed) {
            c.map(4); c.integer(1); c.integer(1); c.integer(3); c.integer(-8);
            c.integer(-1); c.integer(6); c.integer(-2); c.bytes(ed.publicKey());
        } else if (material instanceof MlDsa65Key ml) {
            c.map(3); c.integer(1); c.integer(7); c.integer(3); c.integer(-49);
            c.integer(-1); c.bytes(ml.publicKey());
        } else throw new IllegalArgumentException("Unsupported v0.1 method material");
    }
}
