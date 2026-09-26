package org.openidentity.core;

import java.util.Objects;

public record VerificationMethod(VerificationMethodId id, CoseKey key) implements Comparable<VerificationMethod> {
    public VerificationMethod { Objects.requireNonNull(id, "id"); Objects.requireNonNull(key, "key"); }
    @Override public int compareTo(VerificationMethod other) { return id.compareTo(other.id); }
}
