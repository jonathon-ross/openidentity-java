package org.openidentity.core;
import java.util.List;
public record RecoveryPolicy(int threshold, List<VerificationMethod> methods) implements AuthorityPolicy {
 public static final int VERSION = 1;
 public RecoveryPolicy { methods = Policies.canonicalMethods(methods); threshold = Policies.validateThreshold(threshold, methods.size()); }
 public static RecoveryPolicy single(VerificationMethod method) { return new RecoveryPolicy(1, List.of(method)); }
}
