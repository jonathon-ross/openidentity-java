package org.openidentity.core;

import java.util.List;

public interface AuthorityPolicy { int threshold(); List<VerificationMethod> methods(); default boolean isSingle() { return threshold() == 1 && methods().size() == 1; } }
