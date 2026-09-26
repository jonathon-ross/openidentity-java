package org.openidentity.core;

import java.security.*;
import java.util.*;

public final class MultihashSha256 {
  public static final int LENGTH = 34;
  private final byte[] bytes;

  private MultihashSha256(byte[] bytes) {
    this.bytes = bytes;
  }

  public static MultihashSha256 digest(byte[] input) {
    Objects.requireNonNull(input, "input");
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(input);
      byte[] out = new byte[LENGTH];
      out[0] = 0x12;
      out[1] = 0x20;
      System.arraycopy(d, 0, out, 2, d.length);
      return new MultihashSha256(out);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public static MultihashSha256 of(byte[] v) {
    Objects.requireNonNull(v, "value");
    if (v.length != LENGTH || v[0] != 0x12 || v[1] != 0x20)
      throw new IllegalArgumentException("Expected 34-byte SHA2-256 Multihash");
    return new MultihashSha256(v.clone());
  }

  public byte[] bytes() {
    return bytes.clone();
  }

  public boolean equals(Object o) {
    return this == o || o instanceof MultihashSha256 m && Arrays.equals(bytes, m.bytes);
  }

  public int hashCode() {
    return Arrays.hashCode(bytes);
  }
}
