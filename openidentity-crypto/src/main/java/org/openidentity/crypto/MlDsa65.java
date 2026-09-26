package org.openidentity.crypto;

import java.util.Objects;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.openidentity.core.MlDsa65Key;

public final class MlDsa65 {
    public static final int SIGNATURE_LENGTH = 3309;
    private MlDsa65() {}

    public static boolean verify(MlDsa65Key key, byte[] message, byte[] signature) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signature, "signature");
        if (signature.length != SIGNATURE_LENGTH) return false;
        MLDSAPublicKeyParameters publicKey =
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, key.publicKey());
        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, publicKey);
        return verifier.verifySignature(message, signature);
    }
}
