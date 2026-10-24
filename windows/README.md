# VPN013 WG Windows

The corresponding source, modified dependencies, GPL AWG tools source and build
scripts are in the [reviewed source archive](https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/tag/windows-source-1.4.0).

SHA256 of `VPN013WG-1.4.0-windows-source.zip`:
`f7c4a928eecc6e40a1d7b0bcf37bf26d7b6de1b449a2ca26f7cf1ffc2bd83e35`.

The manually triggered Windows workflow uses a standard public Windows runner,
hash-pinned tools and no Actions artifact/cache storage. It publishes an MSI only
after tests of installation, native AWG traffic, repair and uninstall pass.
Publisher signing of the R013 application/MSI is absent. The included original
Wintun driver remains signed by its vendor. The private release-metadata signing
key is kept offline and is never available to Actions.

This is an independent R013 client; upstream Amnezia/WireGuard licenses and
credits are retained. It contains no customer configurations, bot source or keys.

