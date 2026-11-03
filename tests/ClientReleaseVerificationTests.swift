import Foundation

@main struct ClientReleaseVerificationTests {
    static func main() {
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        var verifier = ClientReleaseVerification(limit: 3)
        precondition(verifier.acceptsResponse(status: 200, contentLength: -1))
        precondition(verifier.acceptsResponse(status: 200, contentLength: 3))
        precondition(!verifier.acceptsResponse(status: 302, contentLength: 3))
        precondition(!verifier.acceptsResponse(status: 200, contentLength: 0))
        precondition(!verifier.acceptsResponse(status: 200, contentLength: 4))
        precondition(!verifier.acceptsResponse(status: 200, contentLength: -2))
        precondition(verifier.append(Data("a".utf8)))
        precondition(verifier.append(Data("bc".utf8)))
        precondition(!verifier.append(Data("d".utf8)))
        precondition(verifier.byteCount == 3 && verifier.matches(digest))
        var bad = ClientReleaseVerification(limit: 3)
        precondition(bad.append(Data("abd".utf8)))
        precondition(!bad.matches(digest))
        var empty = ClientReleaseVerification(limit: 3)
        precondition(!empty.matches(digest))
        func allowed(_ value: String, count: Int = 1) -> Bool {
            guard let url = URL(string: value) else { return false }
            return ClientReleaseVerification.allowsRedirect(url, count: count)
        }
        precondition(allowed("https://release-assets.githubusercontent.com/example?sig=synthetic"))
        precondition(allowed("https://objects.githubusercontent.com/example"))
        precondition(!allowed("http://release-assets.githubusercontent.com/example"))
        precondition(!allowed("https://release-assets.githubusercontent.com.evil.example/example"))
        precondition(!allowed("https://user@github.com/example"))
        precondition(!allowed("https://github.com:8443/example"))
        precondition(!allowed("https://github.com/example", count: 6))
        print("Release verification: response bounds, streaming hash and redirect policy passed")
    }
}
