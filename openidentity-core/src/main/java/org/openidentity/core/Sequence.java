package org.openidentity.core;

import java.math.BigInteger;
import java.util.Objects;

public record Sequence(BigInteger value) implements Comparable<Sequence> {
  public static final BigInteger MIN = BigInteger.ONE;
  public static final BigInteger MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

  public Sequence {
    Objects.requireNonNull(value, "value");
    if (value.compareTo(MIN) < 0 || value.compareTo(MAX) > 0)
      throw new IllegalArgumentException("Sequence must be in uint64 range 1..2^64-1");
  }

  public static Sequence of(long value) {
    return new Sequence(BigInteger.valueOf(value));
  }

  public Sequence next() {
    if (value.equals(MAX)) throw new ArithmeticException("OpenIdentity sequence exhausted");
    return new Sequence(value.add(BigInteger.ONE));
  }

  public int compareTo(Sequence other) {
    return value.compareTo(other.value);
  }
}
