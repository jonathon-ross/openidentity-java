package org.openidentity.cbor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.openidentity.core.*;

public final class OpenIdentityCborDecoder {
  private OpenIdentityCborDecoder() {}

  public static IdentityState decodeState(byte[] bytes) {
    CborReader reader = new CborReader(bytes);
    Object root = reader.read();
    if (!reader.exhausted())
      throw new IllegalArgumentException("Trailing bytes after IdentityState");
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
      default ->
          throw new IllegalArgumentException("Unsupported IdentityState version: " + version);
    };
  }

  private static ControllerPolicy controllerPolicy(Object value) {
    PolicyParts p = policy(value);
    return new ControllerPolicy(p.threshold(), p.methods());
  }

  private static AssertionPolicy assertionPolicy(Object value) {
    PolicyParts p = policy(value);
    return new AssertionPolicy(p.threshold(), p.methods());
  }

  private static PolicyParts policy(Object value) {
    Map<Object, Object> p = map(value);
    int type = integer(p.get(BigInteger.ONE)).intValueExact();
    if (type == 1) return new PolicyParts(1, methods(p.get(BigInteger.TWO)));
    if (type == 2)
      return new PolicyParts(
          integer(p.get(BigInteger.TWO)).intValueExact(), methods(p.get(BigInteger.valueOf(3))));
    throw new IllegalArgumentException("Unsupported policy type: " + type);
  }

  private static List<VerificationMethod> methods(Object value) {
    List<?> values = list(value);
    ArrayList<VerificationMethod> out = new ArrayList<>(values.size());
    for (Object item : values) out.add(method(item));
    return List.copyOf(out);
  }

  private static VerificationMethod method(Object value) {
    Map<Object, Object> m = map(value);
    VerificationMethodId id = VerificationMethodId.of(bytes(m.get(BigInteger.ONE)));
    Map<Object, Object> key = map(m.get(BigInteger.TWO));
    int kty = integer(key.get(BigInteger.ONE)).intValueExact();
    int alg = integer(key.get(BigInteger.valueOf(3))).intValueExact();
    CoseKey material;
    if (kty == 1 && alg == -8) {
      if (integer(key.get(BigInteger.valueOf(-1))).intValueExact() != 6)
        throw new IllegalArgumentException("Unsupported OKP curve");
      material = Ed25519Key.of(bytes(key.get(BigInteger.valueOf(-2))));
    } else if (kty == 7 && alg == -49) {
      material = MlDsa65Key.of(bytes(key.get(BigInteger.valueOf(-1))));
    } else throw new IllegalArgumentException("Unsupported OpenIdentity v0.1 COSE key");
    return new VerificationMethod(id, material);
  }

  @SuppressWarnings("unchecked")
  private static Map<Object, Object> map(Object value) {
    if (!(value instanceof Map<?, ?> m)) throw new IllegalArgumentException("Expected CBOR map");
    return (Map<Object, Object>) m;
  }

  private static List<?> list(Object value) {
    if (!(value instanceof List<?> l)) throw new IllegalArgumentException("Expected CBOR array");
    return l;
  }

  private static BigInteger integer(Object value) {
    if (!(value instanceof BigInteger i))
      throw new IllegalArgumentException("Expected CBOR integer");
    return i;
  }

  private static byte[] bytes(Object value) {
    if (!(value instanceof byte[] b))
      throw new IllegalArgumentException("Expected CBOR byte string");
    return b;
  }

  private record PolicyParts(int threshold, List<VerificationMethod> methods) {}
}
