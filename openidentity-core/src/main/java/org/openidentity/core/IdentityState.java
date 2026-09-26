package org.openidentity.core;

public sealed interface IdentityState permits IdentityStateV1, IdentityStateV2 {
  int stateVersion();

  IdentityId identity();

  Sequence sequence();

  IdentityStatus status();

  ControllerPolicy controllerPolicy();

  RecoveryCommitment recoveryCommitment();
}
