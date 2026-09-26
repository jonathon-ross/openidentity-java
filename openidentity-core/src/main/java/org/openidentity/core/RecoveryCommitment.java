package org.openidentity.core;

import java.util.Objects;

public record RecoveryCommitment(MultihashSha256 multihash) {
  public RecoveryCommitment {
    Objects.requireNonNull(multihash, "multihash");
  }

  public byte[] bytes() {
    return multihash.bytes();
  }
}
