package org.openidentity.operations;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.*;import java.io.*;import java.math.BigInteger;import java.util.*;import java.util.HexFormat;
import org.junit.jupiter.api.Test;import org.openidentity.core.*;import org.openidentity.crypto.*;
class RotateControllerTransitionTest {
 static final ObjectMapper J=new ObjectMapper();static final HexFormat H=HexFormat.of();
 @Test void v04RotateProducesFrozenStateAndHash()throws Exception{
  JsonNode v=vector("V04"); ControllerPolicy oldp=policy(v,"old"); ControllerPolicy newp=policy(v,"new");
  IdentityStateV1 current=new IdentityStateV1(IdentityId.of(hex(v,"identityHex")),new Sequence(BigInteger.ONE),IdentityStatus.ACTIVE,oldp,null);
  RotateControllerOperation op=new RotateControllerOperation(current.identity(),new Sequence(BigInteger.valueOf(2)),new StateHash(MultihashSha256.of(hex(v,"previousStateHashHex"))),newp);
  List<SignatureProof> auth=List.of(proof(v,"oldEd25519MethodIdHex","oldEd25519AuthorizationSignatureHex"),proof(v,"oldMlDsa65MethodIdHex","oldMlDsa65AuthorizationSignatureHex"));
  List<SignatureProof> pop=List.of(proof(v,"newEd25519MethodIdHex","newEd25519PopSignatureHex"),proof(v,"newMlDsa65MethodIdHex","newMlDsa65PopSignatureHex"));
  IdentityStateV1 result=RotateControllerTransition.apply(current,op,auth,pop);
  assertArrayEquals(hex(v,"resultingIdentityStateHex"),org.openidentity.cbor.OpenIdentityCborEncoder.encodeState(result));
  assertArrayEquals(hex(v,"resultingStateHashHex"),RotateControllerTransition.resultingStateHash(current,op,auth,pop).bytes());
 }
 @Test void v04RejectsMissingNewControllerPop()throws Exception{
  JsonNode v=vector("V04");ControllerPolicy oldp=policy(v,"old"),newp=policy(v,"new");
  IdentityStateV1 current=new IdentityStateV1(IdentityId.of(hex(v,"identityHex")),new Sequence(BigInteger.ONE),IdentityStatus.ACTIVE,oldp,null);
  RotateControllerOperation op=new RotateControllerOperation(current.identity(),new Sequence(BigInteger.TWO),new StateHash(MultihashSha256.of(hex(v,"previousStateHashHex"))),newp);
  List<SignatureProof> auth=List.of(proof(v,"oldEd25519MethodIdHex","oldEd25519AuthorizationSignatureHex"),proof(v,"oldMlDsa65MethodIdHex","oldMlDsa65AuthorizationSignatureHex"));
  assertThrows(IllegalArgumentException.class,()->RotateControllerTransition.apply(current,op,auth,List.of(proof(v,"newEd25519MethodIdHex","newEd25519PopSignatureHex"))));
 }
 static ControllerPolicy policy(JsonNode v,String p){return new ControllerPolicy(2,List.of(new VerificationMethod(VerificationMethodId.of(hex(v,p+"Ed25519MethodIdHex")),Ed25519Key.of(hex(v,p+"Ed25519PublicKeyHex"))),new VerificationMethod(VerificationMethodId.of(hex(v,p+"MlDsa65MethodIdHex")),MlDsa65Key.of(hex(v,p+"MlDsa65PublicKeyHex")))));}
 static SignatureProof proof(JsonNode v,String id,String sig){return new SignatureProof(VerificationMethodId.of(hex(v,id)),hex(v,sig));}
 static JsonNode vector(String id)throws Exception{try(InputStream in=RotateControllerTransitionTest.class.getResourceAsStream("/openidentity-v0.1.1/cryptographic-agility-v0.1.json")){JsonNode r=J.readTree(in);for(JsonNode v:r.path("valid"))if(id.equals(v.path("id").asText()))return v;throw new AssertionError(id);}}
 static byte[] hex(JsonNode n,String f){return H.parseHex(n.path(f).asText());}
}
