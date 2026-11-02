// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
#if os(iOS)
import UIKit
#endif

class TunnelImporter {
    // A legacy and newer file may both contain the same I <t> text even
    // though it generates a different timestamp width. Ask only when both
    // parsers can accept the configuration and no newer-only field identifies it.
    static func needsVersionChoice(_ configuration: TunnelConfiguration) -> Bool {
        let i = configuration.interface
        guard !i.legacyAWG15, i.cookieReplyPacketJunkSize == nil, i.transportPacketJunkSize == nil,
              i.headerProtectionKey == nil, i.contentPaddingAddition == nil, i.rekeyAfterTime == nil,
              i.rekeyTimeout == nil, i.rejectAfterTime == nil, i.keepaliveTimeout == nil,
              i.maxHandshakeAttempts == nil, i.randomTrailers == nil, i.disableCookies == nil else { return false }
        let initial = [i.specialJunk1, i.specialJunk2, i.specialJunk3, i.specialJunk4, i.specialJunk5]
        return VPN013PrimaryResourceBudget.needsLegacyVersionChoice(initialPackets: initial)
    }

    static func importFromFile(urls: [URL], into tunnelsManager: TunnelsManager, sourceVC: AnyObject?, errorPresenterType: ErrorPresenterProtocol.Type, completionHandler: (() -> Void)? = nil) {
        guard !urls.isEmpty else {
            completionHandler?()
            return
        }
        #if os(iOS)
        // The bot's optional access document is authoritative for this ZIP only.
        // Old stock archives without it continue through the unchanged importer.
        do {
            var document: ClientAccessDocument?
            for url in urls where url.pathExtension.lowercased() == "zip" {
                let entries = try ZipArchive.unarchive(url: url, requiredFileExtensions: ["json"]).filter { $0.fileBaseName == ClientUpdateProtocol.manifestName }
                guard entries.count <= 1, document == nil || entries.isEmpty else { throw ClientUpdateError.invalidDocument }
                if let entry = entries.first { document = try ClientAccessDocument.decode(entry.contents) }
            }
            if let document = document {
                guard urls.count == 1 else { throw ClientUpdateError.invalidDocument }
                ClientUpdateCoordinator.shared.importDocument(document, manager: tunnelsManager) { error in
                    let message = error?.localizedDescription ?? "Заявка №\(document.snapshot.orderID) связана с приложением. Серверы и режим Авто будут обновляться при открытии приложения и по кнопке «Обновить»."
                    errorPresenterType.showErrorAlert(title: error == nil ? "Заявка подключена" : "Обновление конфигураций", message: message, from: sourceVC, onPresented: completionHandler)
                }
                return
            }
        } catch {
            errorPresenterType.showErrorAlert(title: "Документ заявки не принят", message: error.localizedDescription, from: sourceVC, onPresented: completionHandler)
            return
        }
        #endif
        let dispatchGroup = DispatchGroup()
        var configs = [TunnelConfiguration?]()
        var lastFileImportErrorText: (title: String, message: String)?
        for url in urls {
            if url.pathExtension.lowercased() == "zip" {
                dispatchGroup.enter()
                ZipImporter.importConfigFiles(from: url) { result in
                    switch result {
                    case .failure(let error):
                        lastFileImportErrorText = error.alertText
                    case .success(let configsInZip):
                        configs.append(contentsOf: configsInZip)
                    }
                    dispatchGroup.leave()
                }
            } else { /* if it is not a zip, we assume it is a conf */
                let fileName = url.lastPathComponent
                let fileBaseName = url.deletingPathExtension().lastPathComponent.trimmingCharacters(in: .whitespacesAndNewlines)
                dispatchGroup.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    let fileContents: String
                    do {
                        fileContents = try VPN013PrimaryResourceBudget.readConfigFile(url)
                    } catch let error {
                        DispatchQueue.main.async {
                            if let configError = error as? VPN013PrimaryResourceBudget.ConfigReadError {
                                let message: String
                                switch configError {
                                case .tooLarge: message = "Файл конфигурации превышает 1 МиБ."
                                case .invalidEncoding: message = "Файл конфигурации должен быть текстовым файлом UTF-8, UTF-16 или UTF-32."
                                }
                                lastFileImportErrorText = (title: "Файл конфигурации не принят", message: message)
                            } else if let cocoaError = error as? CocoaError, cocoaError.isFileError {
                                lastFileImportErrorText = (title: tr("alertCantOpenInputConfFileTitle"), message: error.localizedDescription)
                            } else {
                                lastFileImportErrorText = (title: tr("alertCantOpenInputConfFileTitle"), message: tr(format: "alertCantOpenInputConfFileMessage (%@)", fileName))
                            }
                            configs.append(nil)
                            dispatchGroup.leave()
                        }
                        return
                    }
                    var parseError: Error?
                    var tunnelConfiguration: TunnelConfiguration?
                    do {
                        tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: fileContents, called: fileBaseName)
                    } catch let error {
                        parseError = error
                    }
                    DispatchQueue.main.async {
                        if parseError != nil {
                            if let parseError = parseError as? WireGuardAppError {
                                lastFileImportErrorText = parseError.alertText
                            } else {
                                lastFileImportErrorText = (title: tr("alertBadConfigImportTitle"), message: tr(format: "alertBadConfigImportMessage (%@)", fileName))
                            }
                        }
                        configs.append(tunnelConfiguration)
                        dispatchGroup.leave()
                    }
                }
            }
        }
        dispatchGroup.notify(queue: .main) {
            let undecided = configs.compactMap { $0 }.filter { needsVersionChoice($0) }
            func addSelectedConfigurations() {
                tunnelsManager.addMultiple(tunnelConfigurations: configs.compactMap { $0 }) { numberSuccessful, lastAddError in
                    if !configs.isEmpty && numberSuccessful == configs.count {
                        completionHandler?()
                        return
                    }
                    let alertText: (title: String, message: String)?
                    if urls.count == 1 {
                        if urls.first!.pathExtension.lowercased() == "zip" && !configs.isEmpty {
                            let summary = tr(format: "alertImportedFromZipMessage (%1$d of %2$d)", numberSuccessful, configs.count)
                            let reason = lastAddError?.alertText.message ?? lastFileImportErrorText?.message
                            alertText = (title: numberSuccessful == 0 ? (lastAddError?.alertText.title ?? tr(format: "alertImportedFromZipTitle (%d)", numberSuccessful)) : tr(format: "alertImportedFromZipTitle (%d)", numberSuccessful),
                                         message: summary + (reason.map { "\n\n" + $0 } ?? ""))
                        } else {
                            alertText = lastFileImportErrorText ?? lastAddError?.alertText
                        }
                    } else {
                        alertText = (title: tr(format: "alertImportedFromMultipleFilesTitle (%d)", numberSuccessful),
                                     message: tr(format: "alertImportedFromMultipleFilesMessage (%1$d of %2$d)", numberSuccessful, configs.count))
                    }
                    if let alertText = alertText {
                        errorPresenterType.showErrorAlert(title: alertText.title, message: alertText.message, from: sourceVC, onPresented: completionHandler)
                    } else {
                        completionHandler?()
                    }
                }
            }
            #if os(iOS)
            func chooseVersion(_ index: Int) {
                guard index < undecided.count else { addSelectedConfigurations(); return }
                guard let source = sourceVC as? UIViewController else {
                    errorPresenterType.showErrorAlert(title: "Нужно уточнить версию AmneziaWG",
                        message: "Не удалось открыть выбор версии для импортируемой конфигурации.",
                        from: sourceVC, onPresented: completionHandler)
                    return
                }
                let config = undecided[index]
                let alert = UIAlertController(title: "Уточните версию AmneziaWG",
                    message: "Для «\(config.name ?? "конфигурации")» параметр I может означать разные версии. Выберите версию сервера.",
                    preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "AmneziaWG 1.5", style: .default) { _ in
                    config.interface.legacyAWG15 = true; chooseVersion(index + 1)
                })
                alert.addAction(UIAlertAction(title: "AmneziaWG 2.0 / 3.1", style: .default) { _ in
                    config.interface.legacyAWG15 = false; chooseVersion(index + 1)
                })
                alert.addAction(UIAlertAction(title: "Отменить импорт", style: .cancel) { _ in completionHandler?() })
                (source.presentedViewController ?? source).present(alert, animated: true)
            }
            chooseVersion(0)
            #else
            if undecided.isEmpty { addSelectedConfigurations() }
            else {
                errorPresenterType.showErrorAlert(title: "Нужно уточнить версию AmneziaWG",
                    message: "Импорт отменён: этот файл не указывает версию однозначно.",
                    from: sourceVC, onPresented: completionHandler)
            }
            #endif
        }
    }
}
