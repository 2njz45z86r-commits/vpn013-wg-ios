// SPDX-License-Identifier: MIT
import org.amnezia.awg.r013.SubscriptionRequest;
import java.net.URI;

public final class SubscriptionRequestTest {
    private static int checks;
    private static void check(boolean yes) { if (!yes) throw new AssertionError("request check " + checks); checks++; }
    public static void main(String[] args) throws Exception {
        String path = "/sub/" + "a".repeat(43);
        for (int port : new int[]{8443,8444}) {
            String original = "https://connect.vpn555.shop:" + port + path;
            check(SubscriptionRequest.compatibilityURL(original).equals(original + "?format=uri"));
            String query = original + "?option=a%2Bb";
            String compact = SubscriptionRequest.compatibilityURL(query);
            check(compact.equals(query + "&format=uri"));
            check(new URI(query).getRawAuthority().equals(new URI(compact).getRawAuthority()));
            check(new URI(query).getRawPath().equals(new URI(compact).getRawPath()));
            check(SubscriptionRequest.compatibilityURL(original + "?").equals(original + "?format=uri"));
            for (String explicit : new String[]{"?format=json", "?%66ormat=base64", "?format=uri"})
                check(SubscriptionRequest.compatibilityURL(original+explicit).equals(original+explicit));
        }
        for (String original : new String[]{
                "https://another.example:8443"+path,
                "https://connect.vpn555.shop.evil.example:8443"+path,
                "https://connect.vpn555.shop:443"+path,
                "http://connect.vpn555.shop:8443"+path,
                "https://user@connect.vpn555.shop:8443"+path,
                "https://connect.vpn555.shop:8443"+path+"#fragment",
                "https://connect.vpn555.shop:8443/sub/short",
                "https://connect.vpn555.shop:8443/not-sub/"+"a".repeat(43)})
            check(SubscriptionRequest.compatibilityURL(original).equals(original));
        System.out.println(checks + " subscription request checks passed");
    }
}
