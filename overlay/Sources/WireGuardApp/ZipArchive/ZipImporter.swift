// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

class ZipImporter {
    private struct RawFile: Hashable { let name: String; let contents: Data }
    private struct DecodedFile: Hashable { let name: String; let contents: Data }
    static func importConfigFiles(from url: URL, completion: @escaping (Result<[TunnelConfiguration?], ZipArchiveError>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var unarchivedFiles: [(fileBaseName: String, contents: Data)]
            do {
                unarchivedFiles = try ZipArchive.unarchive(url: url, requiredFileExtensions: ["conf"])
                for (index, unarchivedFile) in unarchivedFiles.enumerated().reversed() {
                    let fileBaseName = unarchivedFile.fileBaseName
                    let trimmedName = fileBaseName.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmedName.isEmpty {
                        unarchivedFiles[index].fileBaseName = trimmedName
                    } else {
                        unarchivedFiles.remove(at: index)
                    }
                }

                if unarchivedFiles.isEmpty {
                    throw ZipArchiveError.noTunnelsInZipArchive
                }
            } catch let error as ZipArchiveError {
                DispatchQueue.main.async { completion(.failure(error)) }
                return
            } catch {
                fatalError()
            }

            unarchivedFiles.sort { TunnelsManager.tunnelNameIsLessThan($0.fileBaseName, $1.fileBaseName) }
            var configs: [TunnelConfiguration?] = []
            var uniqueFiles = Set<RawFile>()
            var uniqueDecodedFiles = Set<DecodedFile>()
            for file in unarchivedFiles {
                // Android/iPhone folders can contain identical copies. A duplicate is
                // not a failed import and must not inflate the result denominator.
                guard uniqueFiles.insert(RawFile(name: file.fileBaseName, contents: file.contents)).inserted else { continue }
                guard let fileContents = try? VPN013PrimaryResourceBudget.decodeConfig(file.contents) else {
                    configs.append(nil); continue
                }
                // Identical Android/iPhone copies may use different text
                // encodings. Deduplicate only when both name and decoded UTF-8 bytes
                // are equal; different configurations remain separate.
                guard uniqueDecodedFiles.insert(DecodedFile(name: file.fileBaseName, contents: Data(fileContents.utf8))).inserted else { continue }
                guard let tunnelConfig = try? TunnelConfiguration(fromWgQuickConfig: fileContents, called: file.fileBaseName) else {
                    configs.append(nil); continue
                }
                configs.append(tunnelConfig)
            }
            #if targetEnvironment(simulator) && DEBUG
            if ProcessInfo.processInfo.arguments.contains("--vpn013-test-import") {
                MockTunnels.verifyImportedArchive(configs)
            }
            #endif
            guard configs.contains(where: { $0 != nil }) else {
                DispatchQueue.main.async { completion(.failure(.invalidConfiguration)) }; return
            }
            DispatchQueue.main.async { completion(.success(configs)) }
        }
    }
}
