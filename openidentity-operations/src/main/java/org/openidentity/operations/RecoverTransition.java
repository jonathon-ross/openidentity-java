package org.openidentity.operations;
import java.math.BigInteger;import java.util.*;import org.openidentity.cbor.OpenIdentityCborEncoder;import org.openidentity.core.*;import org.openidentity.crypto.*;
public final class RecoverTransition{
 private RecoverTransition(){}
 public static IdentityState apply(IdentityState current,RecoverOperation op,List<SignatureProof> recoveryProofs,List<SignatureProof> controllerPops){
  Objects.requireNonNull(current);Objects.requireNonNull(op);Objects.requireNonNull(recoveryProofs);Objects.requireNonNull(controllerPops);
  if(!current.identity().equals(op.identity()))throw new IllegalArgumentException("Identity mismatch");
  if(!op.sequence().value().equals(current.sequence().value().add(BigInteger.ONE)))throw new IllegalArgumentException("Sequence must equal current sequence + 1");
  if(!StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current)).equals(op.previousStateHash()))throw new IllegalArgumentException("previousStateHash mismatch");
  if(current.recoveryCommitment()==null)throw new IllegalArgumentException("Current state has no recovery commitment");
  RecoveryCommitment revealed=new RecoveryCommitment(MultihashSha256.digest(OpenIdentityCborEncoder.encodeRecoveryPolicy(op.currentRecoveryPolicy())));
  if(!revealed.equals(current.recoveryCommitment()))throw new IllegalArgumentException("Revealed RecoveryPolicy does not match current commitment");
  if(op.newRecoveryCommitment().equals(current.recoveryCommitment()))throw new IllegalArgumentException("New recovery commitment must rotate");
  byte[] bytes=op.encode();
  if(!RecoveryPolicyVerifier.verify(op.currentRecoveryPolicy(),bytes,recoveryProofs))throw new IllegalArgumentException("RecoveryPolicy authorization failed");
  if(!ProofOfPossessionVerifier.verifyAll(op.newControllerPolicy(),bytes,controllerPops))throw new IllegalArgumentException("New controller proof of possession failed");
  if(current instanceof IdentityStateV2 v2)return new IdentityStateV2(current.identity(),op.sequence(),IdentityStatus.ACTIVE,op.newControllerPolicy(),op.newRecoveryCommitment(),v2.assertionPolicy());
  return new IdentityStateV1(current.identity(),op.sequence(),IdentityStatus.ACTIVE,op.newControllerPolicy(),op.newRecoveryCommitment());
 }
}
