// SPDX-License-Identifier: Apache-2.0
package org.amnezia.awg.r013;
import java.io.InputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Immutable release-pinned IP policy; never an online rule loader. */
public final class RussianIPPolicy {
 public static final String SHA256="0b947f48b2053a98616b33d9f5074aa0a8d15d092a7025d9080e3f2c29061679";
 public record Prefix(InetAddress address,int bits) {}
 private static volatile List<Prefix> cached;
 private RussianIPPolicy(){}
 public static List<Prefix> load(InputStream input)throws IOException {
  try(input){
   java.io.ByteArrayOutputStream buffer=new java.io.ByteArrayOutputStream();byte[] part=new byte[8192];
   for(int n;(n=input.read(part))!=-1;){if(buffer.size()+n>524288)throw new IOException("RU policy resource bound");buffer.write(part,0,n);}
   byte[] raw=buffer.toByteArray();
   byte[] digest=MessageDigest.getInstance("SHA-256").digest(raw);StringBuilder hex=new StringBuilder();for(byte b:digest)hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
   if(!SHA256.contentEquals(hex))throw new IOException("RU policy hash mismatch");
   List<Prefix> result=new ArrayList<>();
   for(String row:new String(raw,StandardCharsets.US_ASCII).split("\n")){
    if(!row.matches("[0-9a-fA-F:.]+/[0-9]{1,3}"))throw new IOException("Invalid RU prefix");
    String[] value=row.split("/");InetAddress address=InetAddress.getByName(value[0]);int bits=Integer.parseInt(value[1]);
    byte[] bytes=address.getAddress();if(bits<=0||bits>bytes.length*8)throw new IOException("Invalid RU mask");
    for(int bit=bits;bit<bytes.length*8;bit++)if((bytes[bit/8]&(1<<(7-bit%8)))!=0)throw new IOException("Noncanonical RU prefix");
    result.add(new Prefix(address,bits));
   }
   if(result.size()!=10838)throw new IOException("Incomplete RU policy");
   return Collections.unmodifiableList(result);
  }catch(IOException e){throw e;}catch(Exception e){throw new IOException("Invalid embedded RU policy",e);}
 }
 public static synchronized List<Prefix> get(InputStream input)throws IOException {
  if(cached==null)cached=load(input);else input.close();return cached;
 }
 /** Only exclusions intersecting routes actually captured by this tunnel.
  * A narrower captured prefix inside RU must itself be excluded, otherwise
  * Android's longest-prefix match would keep it in the VPN. */
 public static List<Prefix> intersections(List<Prefix> ru,List<Prefix> captured) {
  java.util.LinkedHashSet<Prefix> result=new java.util.LinkedHashSet<>();
  for(Prefix direct:ru)for(Prefix tunnel:captured){
   if(direct.address().getAddress().length!=tunnel.address().getAddress().length)continue;
   int bits=Math.min(direct.bits(),tunnel.bits());
   byte[] a=direct.address().getAddress(),b=tunnel.address().getAddress();boolean same=true;
   for(int bit=0;bit<bits;bit++)if(((a[bit/8]^b[bit/8])&(1<<(7-bit%8)))!=0){same=false;break;}
   if(same)result.add(direct.bits()>=tunnel.bits()?direct:tunnel);
  }
  return Collections.unmodifiableList(new ArrayList<>(result));
 }
}
