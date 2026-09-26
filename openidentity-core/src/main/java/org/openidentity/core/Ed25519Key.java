package org.openidentity.core;

import java.util.Arrays;
import java.util.Objects;

public final class Ed25519Key implements CoseKey {
    public static final int LENGTH = 32;
    private final byte[] bytes;

    private Ed25519Key(byte[] bytes) { this.bytes = bytes; }

    public static Ed25519Key of(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length != LENGTH) throw new IllegalArgumentException("Ed25519 key must be exactly 32 bytes");
        return new Ed25519Key(bytes.clone());
    }

    @Override public int coseKeyType() { return 1; }
    @Override public int coseAlgorithm() { return -8; }
    public int coseCurve() { return 6; }
    @Override public byte[] publicKey() { return bytes.clone(); }
    @Override public boolean equals(Object other) { return this == other || other instanceof Ed25519Key that && Arrays.equals(bytes, that.bytes); }
    @Override public int hashCode() { return Arrays.hashCode(bytes); }
}
