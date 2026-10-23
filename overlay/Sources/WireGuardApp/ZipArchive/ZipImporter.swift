// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

class ZipImporter {
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
            var uniqueFiles: [(fileBaseName: String, contents: Data)] = []
            for file in unarchivedFiles {
                // Android/iPhone folders can contain identical copies. A duplicate is
                // not a failed import and must not inflate the result denominator.
                if uniqueFiles.contains(where: { $0 == file }) { continue }
                uniqueFiles.append(file)
                guard let fileContents = String(data: file.contents, encoding: .utf8),
                      let tunnelConfig = try? TunnelConfiguration(fromWgQuickConfig: fileContents, called: file.fileBaseName) else {
                    configs.append(nil); continue
                }
                configs.append(tunnelConfig)
            }
            guard configs.contains(where: { $0 != nil }) else {
                DispatchQueue.main.async { completion(.failure(.invalidConfiguration)) }; return
            }
            DispatchQueue.main.async { completion(.success(configs)) }
        }
    }
}
