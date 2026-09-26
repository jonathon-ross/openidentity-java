package org.openidentity.core;

public sealed interface CoseKey permits Ed25519Key, MlDsa65Key {
  int coseKeyType();

  int coseAlgorithm();

  byte[] publicKey();
}
