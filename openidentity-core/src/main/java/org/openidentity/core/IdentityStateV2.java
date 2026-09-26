package org.openidentity.core;
import java.util.Objects;
public record IdentityStateV2(IdentityId identity, Sequence sequence, IdentityStatus status, ControllerPolicy controllerPolicy, RecoveryCommitment recoveryCommitment, AssertionPolicy assertionPolicy) implements IdentityState { public IdentityStateV2 { Objects.requireNonNull(identity,"identity"); Objects.requireNonNull(sequence,"sequence"); Objects.requireNonNull(status,"status"); Objects.requireNonNull(controllerPolicy,"controllerPolicy"); } public int stateVersion(){return 2;} }
