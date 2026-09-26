package org.openidentity.credentials;
import java.util.*;import org.openidentity.cbor.OpenIdentityCborEncoder;import org.openidentity.core.*;import org.openidentity.crypto.*;
public final class CredentialVerifier{
 private CredentialVerifier(){}
 public static boolean verify(byte[] credentialBytes,IdentityId issuer,StateHash issuanceStateHash,IdentityState historicalState,List<SignatureProof> proofs){
  Objects.requireNonNull(credentialBytes);Objects.requireNonNull(issuer);Objects.requireNonNull(issuanceStateHash);Objects.requireNonNull(historicalState);Objects.requireNonNull(proofs);
  if(!(historicalState instanceof IdentityStateV2 v2))return false;
  if(!historicalState.identity().equals(issuer))return false;
  if(!StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(historicalState)).equals(issuanceStateHash))return false;
  AssertionPolicy policy=v2.assertionPolicy();if(policy==null)return false;
  return PolicyVerifier.verify(policy,CredentialSigningInputs.credential(credentialBytes),proofs);
 }
}
