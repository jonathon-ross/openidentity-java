package org.openidentity.operations;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
public record CreateOperation(IdentityId identity, ControllerPolicy controllerPolicy, RecoveryCommitment recoveryCommitment) implements OpenIdentityOperation {
    public CreateOperation { Objects.requireNonNull(identity,"identity"); Objects.requireNonNull(controllerPolicy,"controllerPolicy"); }
    public int protocolVersion(){ return 1; }
    public OperationType operationType(){ return OperationType.CREATE; }
    public Sequence sequence(){ return new Sequence(java.math.BigInteger.ONE); }
    public byte[] encode(){ return OpenIdentityCborEncoder.encodeCreateOperation(identity,controllerPolicy,recoveryCommitment); }
}
