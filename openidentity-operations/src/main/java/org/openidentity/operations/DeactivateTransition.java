package org.openidentity.operations;
import java.math.BigInteger;import java.util.*;import org.openidentity.cbor.OpenIdentityCborEncoder;import org.openidentity.core.*;import org.openidentity.crypto.*;
public final class DeactivateTransition{
 private DeactivateTransition(){}
 public static IdentityState apply(IdentityState current,DeactivateOperation op,List<SignatureProof> auth){
  Objects.requireNonNull(current);Objects.requireNonNull(op);Objects.requireNonNull(auth);
  if(current.status()!=IdentityStatus.ACTIVE)throw new IllegalArgumentException("Current identity must be ACTIVE");
  if(!current.identity().equals(op.identity()))throw new IllegalArgumentException("Identity mismatch");
  if(!op.sequence().value().equals(current.sequence().value().add(BigInteger.ONE)))throw new IllegalArgumentException("Sequence must equal current sequence + 1");
  if(!StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current)).equals(op.previousStateHash()))throw new IllegalArgumentException("previousStateHash mismatch");
  if(!PolicyVerifier.verify(current.controllerPolicy(),SigningInputs.operation(op.encode()),auth))throw new IllegalArgumentException("Current ControllerPolicy authorization failed");
  if(current instanceof IdentityStateV2 v2)return new IdentityStateV2(current.identity(),op.sequence(),IdentityStatus.DEACTIVATED,current.controllerPolicy(),current.recoveryCommitment(),v2.assertionPolicy());
  return new IdentityStateV1(current.identity(),op.sequence(),IdentityStatus.DEACTIVATED,current.controllerPolicy(),current.recoveryCommitment());
 }
}
