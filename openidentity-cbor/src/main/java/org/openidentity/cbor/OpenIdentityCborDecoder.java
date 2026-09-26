package org.openidentity.cbor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.openidentity.core.*;

/** Decodes canonical OpenIdentity protocol structures from deterministic CBOR. */
public final class OpenIdentityCborDecoder {
  private OpenIdentityCborDecoder() {}

  /**
   * Decodes an IdentityState v1 or v2.
   *
   * @param bytes complete encoded state
   * @return immutable decoded state
   * @throws IllegalArgumentException for malformed, trailing, unsupported, or invalid protocol data
   */
  public static IdentityState decodeState(byte[] bytes) {
    CborReader reader = new CborReader(bytes);
    Object root = reader.read();
    if (!reader.exhausted()) {
      throw new IllegalArgumentException("Trailing bytes after IdentityState");
    }
    Map<Object, Object> state = map(root);
    int version = integer(state.get(BigInteger.ONE)).intValueExact();
    IdentityId identity = IdentityId.of(bytes(state.get(BigInteger.TWO)));
    Sequence sequence = new Sequence(integer(state.get(BigInteger.valueOf(3))));
    IdentityStatus status =
        IdentityStatus.fromCode(integer(state.get(BigInteger.valueOf(4))).intValueExact());
    ControllerPolicy controller = controllerPolicy(state.get(BigInteger.valueOf(5)));
    RecoveryCommitment recovery =
        state.containsKey(BigInteger.valueOf(6))
            ? new RecoveryCommitment(MultihashSha256.of(bytes(state.get(BigInteger.valueOf(6)))))
            : null;

    return switch (version) {
      case 1 -> new IdentityStateV1(identity, sequence, status, controller, recovery);
      case 2 ->
          new IdentityStateV2(
              identity,
              sequence,
              status,
              controller,
              recovery,
              state.containsKey(BigInteger.valueOf(7))
                  ? assertionPolicy(state.get(BigInteger.valueOf(7)))
                  : null);
      default -> throw new IllegalArgumentException("Unsupported IdentityState version: " + version);
    };
  }

  private static ControllerPolicy controllerPolicy(Object value) {
    Map<Object, Object> policy = map(value);
    int type = integer(policy.get(BigInteger.ONE)).intValueExact();
    return switch (type) {
      case 1 -> ControllerPolicy.single(method(list(policy.get(BigInteger.TWO)).get(0)));
      case 2 ->
          new ControllerPolicy(
              integer(policy.get(BigInteger.TWO)).intValueExact(),
              methods(policy.get(BigInteger.valueOf(3))));
      default -> throw new IllegalArgumentException("Unsupported ControllerPolicy type: " + type);
    };
  }

  private static AssertionPolicy assertionPolicy(Object value) {
    Map<Object, Object> policy = map(value);
    int type = integer(policy.get(BigInteger.ONE)).intValueExact();
    return switch (type) {
      case 1 -> AssertionPolicy.single(method(list(policy.get(BigInteger.TWO)).get(0)));
      case 2 ->
          new AssertionPolicy(
              integer(policy.get(BigInteger.TWO)).intValueExact(),
              methods(policy.get(BigInteger.valueOf(3))));
      default -> throw new IllegalArgumentException("Unsupported AssertionPolicy type: " + type);
    };
  }

  private static List<VerificationMethod> methods(Object value) {
    List<VerificationMethod> out = new ArrayList<>();
    for (Object item : list(value)) out.add(method(item));
    return List.copyOf(out);
  }

  private static VerificationMethod method(Object value) {
    Map<Object, Object> method = map(value);
    VerificationMethodId id = VerificationMethodId.of(bytes(method.get(BigInteger.ONE)));
    Map<Object, Object> key = map(method.get(BigInteger.TWO));
    int kty = integer(key.get(BigInteger.ONE)).intValueExact();
    int alg = integer(key.get(BigInteger.valueOf(3))).intValueExact();
    if (kty == 1 && alg == -8) {
      return new VerificationMethod(id, Ed25519Key.of(bytes(key.get(BigInteger.valueOf(-2)))));
    }
    if (kty == 7 && alg == -49) {
      return new VerificationMethod(id, MlDsa65Key.of(bytes(key.get(BigInteger.valueOf(-2)))));
    }
    throw new IllegalArgumentException("Unsupported OpenIdentity COSE key");
  }

  @SuppressWarnings("unchecked")
  private static Map<Object, Object> map(Object value) {
    if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException("Expected CBOR map");
    return (Map<Object, Object>) map;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> list(Object value) {
    if (!(value instanceof List<?> list)) throw new IllegalArgumentException("Expected CBOR array");
    return (List<Object>) list;
  }

  private static BigInteger integer(Object value) {
    if (!(value instanceof BigInteger integer))
      throw new IllegalArgumentException("Expected CBOR integer");
    return integer;
  }

  private static byte[] bytes(Object value) {
    if (!(value instanceof byte[] bytes))
      throw new IllegalArgumentException("Expected CBOR byte string");
    return bytes;
  }
}
