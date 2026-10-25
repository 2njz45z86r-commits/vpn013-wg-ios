// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

enum ZipArchiveError: WireGuardAppError {
    case cantOpenInputZipFile
    case cantOpenOutputZipFileForWriting
    case badArchive
    case noTunnelsInZipArchive
    case invalidConfiguration

    var alertText: AlertText {
        switch self {
        case .invalidConfiguration:
            return ("Конфигурации не распознаны", "ZIP открыт, но ни один файл .conf не удалось разобрать как конфигурацию AmneziaWG. Проверьте формат файлов; новые VPN-ключи создавать не нужно.")
        case .cantOpenInputZipFile:
            return (tr("alertCantOpenInputZipFileTitle"), tr("alertCantOpenInputZipFileMessage"))
        case .cantOpenOutputZipFileForWriting:
            return (tr("alertCantOpenOutputZipFileForWritingTitle"), tr("alertCantOpenOutputZipFileForWritingMessage"))
        case .badArchive:
            return (tr("alertBadArchiveTitle"), tr("alertBadArchiveMessage"))
        case .noTunnelsInZipArchive:
            return (tr("alertNoTunnelsInImportedZipArchiveTitle"), tr("alertNoTunnelsInImportedZipArchiveMessage"))
        }
    }
}

enum ZipArchive {}

extension ZipArchive {

    static func archive(inputs: [(fileName: String, contents: Data)], to destinationURL: URL) throws {
        let destinationPath = destinationURL.path
        guard let zipFile = zipOpen(destinationPath, APPEND_STATUS_CREATE) else {
            throw ZipArchiveError.cantOpenOutputZipFileForWriting
        }
        for input in inputs {
            let fileName = input.fileName
            let contents = input.contents
            zipOpenNewFileInZip(zipFile, fileName.cString(using: .utf8), nil, nil, 0, nil, 0, nil, Z_DEFLATED, Z_DEFAULT_COMPRESSION)
            contents.withUnsafeBytes { rawBufferPointer -> Void in
                zipWriteInFileInZip(zipFile, rawBufferPointer.baseAddress, UInt32(contents.count))
            }
            zipCloseFileInZip(zipFile)
        }
        zipClose(zipFile, nil)
    }

    static func unarchive(url: URL, requiredFileExtensions: [String], strictRoot: Bool = false) throws -> [(fileBaseName: String, contents: Data)] {

        var results = [(fileBaseName: String, contents: Data)]()
        let requiredFileExtensionsLowercased = requiredFileExtensions.map { $0.lowercased() }

        guard let zipFile = unzOpen64(url.path) else {
            throw ZipArchiveError.cantOpenInputZipFile
        }
        defer {
            unzClose(zipFile)
        }
        guard unzGoToFirstFile(zipFile) == UNZ_OK else { throw ZipArchiveError.badArchive }

        var resultOfGoToNextFile: Int32
        var entryCount = 0
        var totalBytes = 0
        repeat {
            entryCount += 1
            guard entryCount <= (strictRoot ? 60 : 512) else { throw ZipArchiveError.badArchive }
            guard unzOpenCurrentFile(zipFile) == UNZ_OK else { throw ZipArchiveError.badArchive }

            let bufferSize = 16384 // 16 KiB
            let fileNameBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: bufferSize)
            fileNameBuffer.initialize(repeating: 0, count: bufferSize)
            let dataBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: bufferSize)

            defer {
                fileNameBuffer.deallocate()
                dataBuffer.deallocate()
            }

            var information = unz_file_info64()
            guard unzGetCurrentFileInfo64(zipFile, &information, fileNameBuffer, UInt(bufferSize), nil, 0, nil, 0) == UNZ_OK,
                  Int(information.size_filename) < bufferSize else { throw ZipArchiveError.badArchive }

            let lastChar = String(cString: fileNameBuffer).suffix(1)
            if strictRoot {
                let name = String(cString: fileNameBuffer)
                guard !name.isEmpty, !name.contains("/"), !name.contains("\\"), !name.contains(".."),
                      !name.contains(where: { $0.isASCII && $0.asciiValue! < 32 }) else { throw ZipArchiveError.badArchive }
            }
            let isDirectory = (lastChar == "/" || lastChar == "\\")
            let fileURL = URL(fileURLWithFileSystemRepresentation: fileNameBuffer, isDirectory: isDirectory, relativeTo: nil)

            if !isDirectory && requiredFileExtensionsLowercased.contains(fileURL.pathExtension.lowercased()) {
                guard information.uncompressed_size <= 1_048_576 else { throw ZipArchiveError.badArchive }
                var unzippedData = Data()
                var bytesRead: Int32 = 0
                repeat {
                    bytesRead = unzReadCurrentFile(zipFile, dataBuffer, UInt32(bufferSize))
                    if bytesRead > 0 {
                        totalBytes += Int(bytesRead)
                        guard unzippedData.count + Int(bytesRead) <= 1_048_576, totalBytes <= 8_388_608 else { throw ZipArchiveError.badArchive }
                        let dataRead = dataBuffer.withMemoryRebound(to: UInt8.self, capacity: bufferSize) {
                            return Data(bytes: $0, count: Int(bytesRead))
                        }
                        unzippedData.append(dataRead)
                    }
                } while bytesRead > 0
                guard bytesRead == 0 else { throw ZipArchiveError.badArchive }
                results.append((fileBaseName: fileURL.deletingPathExtension().lastPathComponent, contents: unzippedData))
            }

            guard unzCloseCurrentFile(zipFile) == UNZ_OK else { throw ZipArchiveError.badArchive }

            resultOfGoToNextFile = unzGoToNextFile(zipFile)
        } while resultOfGoToNextFile == UNZ_OK

        if resultOfGoToNextFile == UNZ_END_OF_LIST_OF_FILE {
            return results
        } else {
            throw ZipArchiveError.badArchive
        }
    }
}
