package org.openidentity.core;

import java.util.Objects;

public record StateHash(MultihashSha256 multihash) {
  public StateHash {
    Objects.requireNonNull(multihash, "multihash");
  }

  public static StateHash fromStateBytes(byte[] canonicalStateBytes) {
    return new StateHash(MultihashSha256.digest(canonicalStateBytes));
  }

  public byte[] bytes() {
    return multihash.bytes();
  }
}
