package org.openidentity.operations;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.*;import java.io.*;import java.math.BigInteger;import java.util.*;import java.util.HexFormat;
import org.junit.jupiter.api.Test;import org.openidentity.cbor.OpenIdentityCborEncoder;import org.openidentity.core.*;import org.openidentity.crypto.*;
class RecoveryTransitionV01Test{
 static final ObjectMapper J=new ObjectMapper();static final HexFormat H=HexFormat.of();
 @Test void r01MatchesFrozenOperationStateAndHash()throws Exception{run("R01",false);}
 @Test void r02ReactivatesV2AndPreservesAssertionPolicy()throws Exception{IdentityState result=run("R02",true);assertInstanceOf(IdentityStateV2.class,result);assertNotNull(((IdentityStateV2)result).assertionPolicy());assertEquals(IdentityStatus.ACTIVE,result.status());}
 IdentityState run(String id,boolean v2)throws Exception{
  JsonNode v=valid(id);RecoveryPolicy rp=recoveryPolicy(v);ControllerPolicy np=newController(v);RecoverOperation op=new RecoverOperation(IdentityId.of(hex(v,"identityHex")),new Sequence(BigInteger.valueOf(v.path("sequence").asLong())),new StateHash(MultihashSha256.of(hex(v,"previousStateHashHex"))),np,rp,new RecoveryCommitment(MultihashSha256.of(hex(v,"newRecoveryCommitmentHex"))));
  assertArrayEquals(hex(v,"operationBytesHex"),op.encode());
  assertArrayEquals(hex(v,"currentRecoveryCommitmentHex"),MultihashSha256.digest(OpenIdentityCborEncoder.encodeRecoveryPolicy(rp)).bytes());
  IdentityState current=source(v,v2);
  List<SignatureProof> recovery=List.of(proof(v,"currentRecoveryEd25519MethodIdHex","recoveryEd25519SignatureHex"),proof(v,"currentRecoveryMlDsa65MethodIdHex","recoveryMlDsa65SignatureHex"));
  List<SignatureProof> pop=List.of(proof(v,"newControllerMethodIdHex","newControllerPopSignatureHex"));
  IdentityState result=RecoverTransition.apply(current,op,recovery,pop);
  assertArrayEquals(hex(v,"resultingIdentityStateHex"),OpenIdentityCborEncoder.encodeState(result));
  assertArrayEquals(hex(v,"resultingStateHashHex"),StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(result)).bytes());
  return result;
 }
 static IdentityState source(JsonNode v,boolean v2){ControllerPolicy old=oldController(v);RecoveryCommitment rc=new RecoveryCommitment(MultihashSha256.of(hex(v,"currentRecoveryCommitmentHex")));long seq=v2?v.path("sourceSequence").asLong():1;if(v2){JsonNode a;try{a=assertion("A04");}catch(Exception e){throw new RuntimeException(e);}AssertionPolicy ap=new AssertionPolicy(2,List.of(new VerificationMethod(VerificationMethodId.of(hex(a,"assertionEd25519MethodIdHex")),Ed25519Key.of(hex(a,"assertionEd25519PublicKeyHex"))),new VerificationMethod(VerificationMethodId.of(hex(a,"assertionMlDsa65MethodIdHex")),MlDsa65Key.of(hex(a,"assertionMlDsa65PublicKeyHex")))));return new IdentityStateV2(IdentityId.of(hex(v,"identityHex")),new Sequence(BigInteger.valueOf(seq)),IdentityStatus.DEACTIVATED,old,rc,ap);}return new IdentityStateV1(IdentityId.of(hex(v,"identityHex")),new Sequence(BigInteger.ONE),IdentityStatus.ACTIVE,old,rc);}
 static ControllerPolicy oldController(JsonNode v){JsonNode b;try{b=crypto("V02");}catch(Exception e){throw new RuntimeException(e);}return new ControllerPolicy(2,List.of(new VerificationMethod(VerificationMethodId.of(hex(b,"ed25519MethodIdHex")),Ed25519Key.of(hex(b,"ed25519PublicKeyHex"))),new VerificationMethod(VerificationMethodId.of(hex(b,"mlDsa65MethodIdHex")),MlDsa65Key.of(hex(b,"mlDsa65PublicKeyHex")))));}
 static ControllerPolicy newController(JsonNode v){return ControllerPolicy.single(new VerificationMethod(VerificationMethodId.of(hex(v,"newControllerMethodIdHex")),Ed25519Key.of(hex(v,"newControllerPublicKeyHex"))));}
 static RecoveryPolicy recoveryPolicy(JsonNode v){return new RecoveryPolicy(2,List.of(new VerificationMethod(VerificationMethodId.of(hex(v,"currentRecoveryEd25519MethodIdHex")),Ed25519Key.of(hex(v,"currentRecoveryEd25519PublicKeyHex"))),new VerificationMethod(VerificationMethodId.of(hex(v,"currentRecoveryMlDsa65MethodIdHex")),MlDsa65Key.of(hex(v,"currentRecoveryMlDsa65PublicKeyHex")))));}
 static SignatureProof proof(JsonNode v,String i,String s){return new SignatureProof(VerificationMethodId.of(hex(v,i)),hex(v,s));}
 static JsonNode valid(String id)throws Exception{return find("/openidentity-v0.1.1/recovery-v0.1.json","validVectors",id);}
 static JsonNode crypto(String id)throws Exception{return find("/openidentity-v0.1.1/cryptographic-agility-v0.1.json","valid",id);}
 static JsonNode assertion(String id)throws Exception{return find("/openidentity-v0.1.1/assertion-authority-v0.1.json","validVectors",id);}
 static JsonNode find(String res,String array,String id)throws Exception{try(InputStream in=RecoveryTransitionV01Test.class.getResourceAsStream(res)){JsonNode r=J.readTree(in);for(JsonNode v:r.path(array))if(id.equals(v.path("id").asText()))return v;throw new AssertionError(id);}}
 static byte[] hex(JsonNode n,String f){return H.parseHex(n.path(f).asText());}
}
