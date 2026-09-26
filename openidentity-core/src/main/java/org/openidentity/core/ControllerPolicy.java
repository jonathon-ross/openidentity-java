package org.openidentity.core;

import java.util.List;

public record ControllerPolicy(int threshold, List<VerificationMethod> methods)
    implements AuthorityPolicy {
  public ControllerPolicy {
    methods = Policies.canonicalMethods(methods);
    threshold = Policies.validateThreshold(threshold, methods.size());
  }

  public static ControllerPolicy single(VerificationMethod method) {
    return new ControllerPolicy(1, List.of(method));
  }
}
