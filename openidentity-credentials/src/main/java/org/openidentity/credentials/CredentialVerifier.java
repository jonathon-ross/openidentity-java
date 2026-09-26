package org.openidentity.credentials;

import java.util.*;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

public final class CredentialVerifier {
  private CredentialVerifier() {}

  public static VerificationResult verifyResult(
      byte[] credentialBytes,
      IdentityId issuer,
      StateHash issuanceStateHash,
      IdentityState historicalState,
      List<SignatureProof> proofs) {
    Objects.requireNonNull(credentialBytes);
    Objects.requireNonNull(issuer);
    Objects.requireNonNull(issuanceStateHash);
    Objects.requireNonNull(historicalState);
    Objects.requireNonNull(proofs);
    if (!(historicalState instanceof IdentityStateV2 v2))
      return VerificationResult.failure(
          OpenIdentityError.NO_ASSERTION_AUTHORITY,
          "Historical state does not support AssertionPolicy");
    if (!historicalState.identity().equals(issuer))
      return VerificationResult.failure(
          OpenIdentityError.IDENTITY_MISMATCH,
          "Historical state identity differs from credential issuer");
    if (!StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(historicalState))
        .equals(issuanceStateHash))
      return VerificationResult.failure(
          OpenIdentityError.INVALID_ISSUANCE_STATE_HASH,
          "issuanceStateHash does not identify the supplied historical state");
    AssertionPolicy policy = v2.assertionPolicy();
    if (policy == null)
      return VerificationResult.failure(
          OpenIdentityError.NO_ASSERTION_AUTHORITY, "Historical state contains no AssertionPolicy");
    byte[] input = CredentialSigningInputs.credential(credentialBytes);
    Map<VerificationMethodId, VerificationMethod> authorized = new HashMap<>();
    for (VerificationMethod m : policy.methods()) authorized.put(m.id(), m);
    Set<VerificationMethodId> seen = new HashSet<>();
    int valid = 0;
    for (SignatureProof p : proofs) {
      if (p == null || !seen.add(p.methodId()))
        return VerificationResult.failure(
            OpenIdentityError.DUPLICATE_CREDENTIAL_PROOF, "Duplicate credential proof method ID");
      VerificationMethod m = authorized.get(p.methodId());
      if (m == null)
        return VerificationResult.failure(
            OpenIdentityError.UNAUTHORIZED_CREDENTIAL_PROOF,
            "Credential proof method is absent from historical AssertionPolicy");
      if (!SignatureVerifier.verify(m.key(), input, p.signature()))
        return VerificationResult.failure(
            OpenIdentityError.INVALID_CREDENTIAL_SIGNATURE,
            "Credential proof signature is invalid");
      valid++;
    }
    if (valid < policy.threshold())
      return VerificationResult.failure(
          OpenIdentityError.ASSERTION_THRESHOLD_NOT_SATISFIED,
          "Credential proof set does not satisfy historical AssertionPolicy threshold");
    return VerificationResult.success();
  }

  public static boolean verify(
      byte[] credentialBytes,
      IdentityId issuer,
      StateHash issuanceStateHash,
      IdentityState historicalState,
      List<SignatureProof> proofs) {
    return verifyResult(credentialBytes, issuer, issuanceStateHash, historicalState, proofs)
        .valid();
  }
}
