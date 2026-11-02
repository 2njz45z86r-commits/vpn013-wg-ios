"""Run the candidate's actual ZIP deduplication lines against synthetic data."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
source = (root / 'overlay/Sources/WireGuardApp/ZipArchive/ZipImporter.swift').read_text(encoding='utf-8')
start = source.index('    private struct RawFile: Hashable')
end = source.index('    static func importConfigFiles', start)
structs = source[start:end]
start = source.index('            var uniqueFiles = Set<RawFile>()')
end = source.index('                guard let tunnelConfig = try?', start)
loop = source[start:end]
assert loop.count('uniqueDecodedFiles.insert') == 1 and loop.count('uniqueFiles.insert') == 1
out = '''import Foundation
enum ZipDedupProbe {
''' + structs + '''
    static func run(_ unarchivedFiles: [(fileBaseName: String, contents: Data)]) -> [String?] {
        var configs: [String?] = []
''' + loop + '''
                configs.append(file.fileBaseName)
            }
        return configs
    }
}
@main struct ZipDedupTests {
    static func main() {
        let text = "[Interface]\\nAddress = 192.0.2.1/32\\n"
        let utf8 = Data(text.utf8)
        let utf16 = Data([0xff, 0xfe]) + text.data(using: .utf16LittleEndian)!
        let changed = Data((text + "DNS = 192.0.2.2\\n").utf8)
        let bad = Data([0xff, 0x41])
        let input = [(fileBaseName:"same",contents:utf8), (fileBaseName:"same",contents:utf16),
                     (fileBaseName:"same",contents:changed), (fileBaseName:"other",contents:utf8),
                     (fileBaseName:"bad",contents:bad), (fileBaseName:"bad",contents:bad)]
        let result = ZipDedupProbe.run(input)
        precondition(result.count == 4 && result[0] == "same" && result[1] == "same" && result[2] == "other" && result[3] == nil)
        print("ZIPDecodedDedup: 6 inputs, 3 distinct and 1 invalid passed")
    }
}
'''
Path(sys.argv[1]).write_text(out, encoding='utf-8', newline='\n')
