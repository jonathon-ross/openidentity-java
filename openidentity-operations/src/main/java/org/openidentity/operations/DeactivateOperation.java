package org.openidentity.operations;
import java.math.BigInteger;import java.util.Objects;import org.openidentity.cbor.OpenIdentityCborEncoder;import org.openidentity.core.*;
public record DeactivateOperation(IdentityId identity,Sequence sequence,StateHash previousStateHash) implements OpenIdentityOperation{
 public DeactivateOperation{Objects.requireNonNull(identity);Objects.requireNonNull(sequence);Objects.requireNonNull(previousStateHash);if(sequence.value().compareTo(BigInteger.TWO)<0)throw new IllegalArgumentException("DEACTIVATE sequence must be >= 2");}
 public int protocolVersion(){return 1;} public OperationType operationType(){return OperationType.DEACTIVATE;}
 public byte[] encode(){return OpenIdentityCborEncoder.encodeDeactivateOperation(identity,sequence,previousStateHash);}
}
