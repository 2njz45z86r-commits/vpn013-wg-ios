# Russian IP-network split routing

Owner explicitly selected RU IP networks direct, other traffic via VPN on 26 October 2026. This is not domain-suffix routing or a promise that every Russian service has a Russian address. RIR country registration is the list definition, not independently measured geolocation.

`ru-networks.cidr` is a canonical, collapsed IPv4/IPv6 snapshot of RIPE NCC country-resource-list RU. The same exact snapshot is embedded in each client. No runtime download, DNS-based exception or remotely executable rule. Unknown destinations keep the profile route. Keys and persisted profiles are not rewritten.

Native admission, route readback, lifecycle, cancellation, both address families and data preservation must pass before release. Unit/source checks do not prove real route application. Existing strict DNS policy on Windows remains in effect. Do not turn off the firewall to implement bypass.
