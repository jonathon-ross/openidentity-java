package org.openidentity.operations;

import java.math.BigInteger;
import java.util.*;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

public final class RotateControllerTransition {
  private RotateControllerTransition() {}

  public static IdentityStateV1 apply(
      IdentityStateV1 current,
      RotateControllerOperation operation,
      List<SignatureProof> authorizationProofs,
      List<SignatureProof> controllerProofs) {
    Objects.requireNonNull(current);
    Objects.requireNonNull(operation);
    Objects.requireNonNull(authorizationProofs);
    Objects.requireNonNull(controllerProofs);
    if (current.status() != IdentityStatus.ACTIVE)
      throw new OpenIdentityException(
          OpenIdentityError.IDENTITY_NOT_ACTIVE, "Current identity must be ACTIVE");
    if (!current.identity().equals(operation.identity()))
      throw new OpenIdentityException(OpenIdentityError.IDENTITY_MISMATCH, "Identity mismatch");
    if (!operation.sequence().value().equals(current.sequence().value().add(BigInteger.ONE)))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_SEQUENCE, "Sequence must equal current sequence + 1");
    StateHash actual = StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current));
    if (!actual.equals(operation.previousStateHash()))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_PREVIOUS_STATE_HASH, "previousStateHash mismatch");
    byte[] bytes = operation.encode();
    if (!PolicyVerifier.verify(
        current.controllerPolicy(), SigningInputs.operation(bytes), authorizationProofs))
      throw new OpenIdentityException(
          OpenIdentityError.CONTROLLER_THRESHOLD_NOT_SATISFIED,
          "Current ControllerPolicy authorization failed");
    if (!ProofOfPossessionVerifier.verifyAll(
        operation.proposedControllerPolicy(), bytes, controllerProofs))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_PROOF_OF_POSSESSION,
          "Proposed controller proof of possession failed");
    return new IdentityStateV1(
        current.identity(),
        operation.sequence(),
        IdentityStatus.ACTIVE,
        operation.proposedControllerPolicy(),
        current.recoveryCommitment());
  }

  public static StateHash resultingStateHash(
      IdentityStateV1 current,
      RotateControllerOperation op,
      List<SignatureProof> auth,
      List<SignatureProof> pop) {
    return StateHash.fromStateBytes(
        OpenIdentityCborEncoder.encodeState(apply(current, op, auth, pop)));
  }
}
