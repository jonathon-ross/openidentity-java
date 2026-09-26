package org.openidentity.core;
import java.util.Objects;
public record IdentityStateV1(IdentityId identity, Sequence sequence, IdentityStatus status, ControllerPolicy controllerPolicy, RecoveryCommitment recoveryCommitment) { public IdentityStateV1 { Objects.requireNonNull(identity,"identity"); Objects.requireNonNull(sequence,"sequence"); Objects.requireNonNull(status,"status"); Objects.requireNonNull(controllerPolicy,"controllerPolicy"); } public int stateVersion(){return 1;} }
