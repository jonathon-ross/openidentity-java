package org.openidentity.credentials;
import java.util.Objects;import org.openidentity.cbor.OpenIdentityCborEncoder;
public final class CredentialSigningInputs{private CredentialSigningInputs(){}public static byte[] credential(byte[] credentialBytes){Objects.requireNonNull(credentialBytes);return OpenIdentityCborEncoder.encodeCredentialSigningInput(credentialBytes);}}
