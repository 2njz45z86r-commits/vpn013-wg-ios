import Foundation

typealias AlertText = (String, String)
protocol WireGuardAppError: Error { var alertText: AlertText { get } }
func tr(_ input: String) -> String { input }

@main enum Test {
    static func main() throws {
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        func url(_ name: String) -> URL { root.appendingPathComponent(name) }
        func accept(_ name: String, _ strict: Bool = true) -> [(fileBaseName: String, contents: Data)] {
            do { return try ZipArchive.unarchive(url: url(name), requiredFileExtensions: ["conf"], strictRoot: strict) }
            catch { fatalError("Expected accept: " + name) }
        }
        func reject(_ name: String, _ strict: Bool = true) {
            do { _ = try ZipArchive.unarchive(url: url(name), requiredFileExtensions: ["conf"], strictRoot: strict) }
            catch { return }
            fatalError("Expected reject: " + name)
        }
        precondition(accept("flat.zip").count == 1)
        precondition(accept("nested.zip", false).count == 1)
        reject("nested.zip")
        precondition(accept("count60.zip").count == 60)
        reject("count61.zip")
        reject("entry-too-large.zip")
        reject("total-too-large.zip")
        reject("crc.zip")
        reject("truncated.zip")
        let nul = accept("nul.zip")
        precondition(nul.count == 1 && nul[0].fileBaseName == "one")
        print("PASS diagnostic: 10 boundary observations; embedded-NUL name accepted in strictRoot")
    }
}
