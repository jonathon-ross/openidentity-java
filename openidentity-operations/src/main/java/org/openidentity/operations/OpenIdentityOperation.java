package org.openidentity.operations;

import org.openidentity.core.IdentityId;
import org.openidentity.core.OperationType;
import org.openidentity.core.Sequence;

public sealed interface OpenIdentityOperation
    permits CreateOperation,
        RotateControllerOperation,
        SetAssertionPolicyOperation,
        DeactivateOperation,
        RecoverOperation {
  int protocolVersion();

  OperationType operationType();

  IdentityId identity();

  Sequence sequence();

  byte[] encode();
}
