package org.openidentity.core;

import java.util.List;

public record AssertionPolicy(int threshold, List<VerificationMethod> methods)
    implements AuthorityPolicy {
  public AssertionPolicy {
    methods = Policies.canonicalMethods(methods);
    threshold = Policies.validateThreshold(threshold, methods.size());
  }

  public static AssertionPolicy single(VerificationMethod method) {
    return new AssertionPolicy(1, List.of(method));
  }
}
