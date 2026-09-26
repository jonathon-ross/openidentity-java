package org.openidentity.credentials;
import java.util.Base64;
public final class Multibase{
 private static final char[] B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();private Multibase(){}
 public static String base64Url(byte[] b){return "u"+Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
 public static String base58Btc(byte[] input){return "z"+base58(input);}
 private static String base58(byte[] input){if(input.length==0)return "";int zeros=0;while(zeros<input.length&&input[zeros]==0)zeros++;byte[] work=input.clone();char[] out=new char[input.length*2];int os=out.length,is=zeros;while(is<work.length){int rem=0;for(int i=is;i<work.length;i++){int d=Byte.toUnsignedInt(work[i]),t=rem*256+d;work[i]=(byte)(t/58);rem=t%58;}out[--os]=B58[rem];while(is<work.length&&work[is]==0)is++;}while(os<out.length&&out[os]==B58[0])os++;while(zeros-->0)out[--os]=B58[0];return new String(out,os,out.length-os);}
}
