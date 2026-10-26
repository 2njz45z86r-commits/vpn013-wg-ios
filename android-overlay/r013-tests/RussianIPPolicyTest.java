import org.amnezia.awg.r013.RussianIPPolicy;
import java.io.*;
import java.nio.file.*;
public final class RussianIPPolicyTest {
 public static void main(String[] args)throws Exception{
  byte[] raw=Files.readAllBytes(Path.of("tunnel/src/main/assets/ru-networks.cidr"));
  var rows=RussianIPPolicy.load(new ByteArrayInputStream(raw));if(rows.size()!=10838)throw new AssertionError();
  long v4=rows.stream().filter(p->p.address().getAddress().length==4).count();if(v4!=8671)throw new AssertionError();
  try{rows.clear();throw new AssertionError();}catch(UnsupportedOperationException expected){}
  raw[0]^=1;try{RussianIPPolicy.load(new ByteArrayInputStream(raw));throw new AssertionError();}catch(IOException expected){}
  try{RussianIPPolicy.load(new ByteArrayInputStream(new byte[524289]));throw new AssertionError();}catch(IOException expected){}
  System.out.println("Russian IP policy: canonical IPv4/IPv6, immutable, corrupt and oversized refusal PASS");
 }
}
