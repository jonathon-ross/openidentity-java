package org.openidentity.operations;
import java.math.BigInteger;import java.util.Objects;import org.openidentity.cbor.OpenIdentityCborEncoder;import org.openidentity.core.*;
public record SetAssertionPolicyOperation(IdentityId identity,Sequence sequence,StateHash previousStateHash,AssertionPolicy assertionPolicy) implements OpenIdentityOperation{
 public SetAssertionPolicyOperation{Objects.requireNonNull(identity);Objects.requireNonNull(sequence);Objects.requireNonNull(previousStateHash);if(sequence.value().compareTo(BigInteger.TWO)<0)throw new IllegalArgumentException("SET_ASSERTION_POLICY sequence must be >= 2");}
 public int protocolVersion(){return 1;} public OperationType operationType(){return OperationType.SET_ASSERTION_POLICY;}
 public byte[] encode(){return OpenIdentityCborEncoder.encodeSetAssertionPolicyOperation(identity,sequence,previousStateHash,assertionPolicy);}
}
