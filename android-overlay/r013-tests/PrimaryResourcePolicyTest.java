// SPDX-License-Identifier: MIT
import org.amnezia.awg.config.PrimaryResourcePolicy;
public final class PrimaryResourcePolicyTest {
    private static int checks;
    private static void valid(int count, int min, int max, int[] sizes, String... specs) {
        PrimaryResourcePolicy.validate(count, min, max, sizes, specs); checks++;
    }
    private static void reject(int count, int min, int max, int[] sizes, String... specs) {
        try { PrimaryResourcePolicy.validate(count, min, max, sizes, specs); throw new AssertionError("unsafe config accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    public static void main(String[] args) {
        int[] zero={0,0,0,0}; String[] empty={"","","","",""};
        valid(0,0,0,zero,empty); // Plain WireGuard.
        valid(3,40,70,new int[]{20,30,0,0},"<r 12><rc 4><rd 2><t><b 0xabcdef>","<d><ds><dz 2>","","","");
        valid(64,4096,4096,new int[]{4096,4096,4096,4096},"<r 4096>","<rc 4096>","<rd 4096>","<dz 4096>","<r 4096>");
        valid(1,0,0,zero,"prefix<r +0004 ignored>suffix","<r -0>","<t ignored>","<b AAbb>","");
        reject(65,1,1,zero,empty); reject(65535,65535,65535,zero,empty);
        reject(1,100,99,zero,empty); reject(1,0,4097,zero,empty); reject(1,4097,4097,zero,empty);
        reject(0,0,0,new int[]{4097,0,0,0},empty); reject(0,0,0,new int[]{0,0,-1,0},empty);
        reject(0,0,0,zero,"<r -1>","","","","");
        reject(0,0,0,zero,"<r 999999999999999999999999999999>","","","","");
        reject(0,0,0,zero,"<r 4096><t>","","","","");
        reject(0,0,0,zero,"<r 1", "","","","");
        reject(0,0,0,zero,"<x 1>","","","","");
        reject(0,0,0,zero,"<b abc>","","","","");
        reject(0,0,0,zero,"<b 0xz0>","","","","");
        reject(0,0,0,zero,"<dz -2>","","","","");
        reject(0,0,0,zero,"<r 4096>","<r 4096>","<r 4096>","<r 4096>","<r 4097>");
        reject(0,0,0,zero,"","","","","","");
        System.out.println("PrimaryResourcePolicyTest PASS: " + checks + " checks");
    }
}
