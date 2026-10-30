// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

import java.net.URI;
import java.net.URLDecoder;

/** The issuer's compact URI response avoids downloading routing JSON the native client does not execute. */
public final class SubscriptionRequest {
    private SubscriptionRequest() {}
    public static String compatibilityURL(String original) {
        try {
            URI uri = new URI(original);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null ||
                !"connect.vpn555.shop".equalsIgnoreCase(uri.getHost()) ||
                (uri.getPort() != 8443 && uri.getPort() != 8444) ||
                uri.getRawUserInfo() != null || uri.getRawFragment() != null ||
                uri.getRawPath() == null || !uri.getRawPath().matches("/sub/[A-Za-z0-9_-]{43}")) return original;
            String query = uri.getRawQuery();
            if (query != null) for (String item : query.split("&")) {
                if (URLDecoder.decode(item.split("=", 2)[0], "UTF-8").equals("format")) return original;
            }
            if (query == null) return original + "?format=uri";
            if (query.isEmpty()) return original + "format=uri";
            return original + "&format=uri";
        } catch (Exception ignored) { return original; }
    }
}
