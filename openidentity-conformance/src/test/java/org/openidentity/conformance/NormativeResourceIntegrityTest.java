package org.openidentity.conformance;
import static org.junit.jupiter.api.Assertions.*;import java.io.*;import java.nio.charset.StandardCharsets;import java.security.MessageDigest;import java.util.HexFormat;import org.junit.jupiter.api.Test;
class NormativeResourceIntegrityTest{
 static final String BASE="/openidentity-v0.1.1/";static final String[] FILES={"state-hash-v0.1.json","cryptographic-agility-v0.1.json","signature-envelope-v0.1.json","assertion-authority-v0.1.json","credential-v0.1.json","w3c-credential-projection-v0.1.json","recovery-v0.1.json"};
 @Test void allPinnedProtocolV011ResourcesMatchPublishedSha256()throws Exception{for(String f:FILES){byte[] data=read(f),manifest=read(f+".sha256");String expected=new String(manifest,StandardCharsets.UTF_8).trim().split("\\s+")[0];String actual=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));assertEquals(expected,actual,f);}}
 static byte[] read(String f)throws Exception{try(InputStream in=NormativeResourceIntegrityTest.class.getResourceAsStream(BASE+f)){if(in==null)throw new AssertionError("Missing normative resource "+f);return in.readAllBytes();}}
}
