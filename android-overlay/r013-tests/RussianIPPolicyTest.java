import org.amnezia.awg.r013.RussianIPPolicy;
import java.io.*;
import java.nio.file.*;
public final class RussianIPPolicyTest {
 public static void main(String[] args)throws Exception{
  byte[] raw=Files.readAllBytes(Path.of("tunnel/src/main/assets/ru-networks.cidr"));
  var rows=RussianIPPolicy.load(new ByteArrayInputStream(raw));if(rows.size()!=10838)throw new AssertionError();
  long v4=rows.stream().filter(p->p.address().getAddress().length==4).count();if(v4!=8671)throw new AssertionError();
  var v4Default=new RussianIPPolicy.Prefix(java.net.InetAddress.getByName("0.0.0.0"),0);
  var v6Default=new RussianIPPolicy.Prefix(java.net.InetAddress.getByName("::"),0);
  if(RussianIPPolicy.intersections(rows,java.util.List.of(v4Default,v6Default)).size()!=10838)throw new AssertionError("Full policy changed");
  var foreign=new RussianIPPolicy.Prefix(java.net.InetAddress.getByName("10.13.99.1"),32);
  if(!RussianIPPolicy.intersections(rows,java.util.List.of(foreign)).isEmpty())throw new AssertionError("Unrelated exclusions installed");
  var narrowRU=new RussianIPPolicy.Prefix(java.net.InetAddress.getByName("2.56.24.1"),32);
  if(!RussianIPPolicy.intersections(rows,java.util.List.of(narrowRU,narrowRU)).equals(java.util.List.of(narrowRU)))throw new AssertionError("Narrow RU did not override the captured route exactly once");
  try{rows.clear();throw new AssertionError();}catch(UnsupportedOperationException expected){}
  raw[0]^=1;try{RussianIPPolicy.load(new ByteArrayInputStream(raw));throw new AssertionError();}catch(IOException expected){}
  try{RussianIPPolicy.load(new ByteArrayInputStream(new byte[524289]));throw new AssertionError();}catch(IOException expected){}
  System.out.println("Russian IP policy: canonical IPv4/IPv6, immutable, corrupt and oversized refusal PASS");
 }
}
