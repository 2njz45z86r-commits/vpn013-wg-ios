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

    #if os(iOS)
    static func askVersions(_ entries: [(String, TunnelConfiguration)], sourceVC: AnyObject?, completion: @escaping ([String: Bool]?) -> Void) {
        let undecided = entries.filter { needsVersionChoice($0.1) }
        guard !undecided.isEmpty else { completion([:]); return }
        guard let source = sourceVC as? UIViewController else { completion(nil); return }
        var choices: [String: Bool] = [:]
        func choose(_ index: Int) {
            guard index < undecided.count else { completion(choices); return }
            let (id, config) = undecided[index]
            let alert = UIAlertController(title: "Уточните версию AmneziaWG",
                message: "Для «\(config.name ?? "конфигурации")» параметр I может означать разные версии. Выберите версию сервера.",
                preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "AmneziaWG 1.5", style: .default) { [weak alert] _ in
                choices[id] = true
                if let alert = alert { alert.dismiss(animated: true) { choose(index + 1) } }
                else { choose(index + 1) }
            })
            alert.addAction(UIAlertAction(title: "AmneziaWG 2.0 / 3.1", style: .default) { [weak alert] _ in
                choices[id] = false
                if let alert = alert { alert.dismiss(animated: true) { choose(index + 1) } }
                else { choose(index + 1) }
            })
            alert.addAction(UIAlertAction(title: "Отменить импорт", style: .cancel) { _ in completion(nil) })
            (source.presentedViewController ?? source).present(alert, animated: true)
        }
        choose(0)
    }
    #endif

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
                let entries = try document.snapshot.servers.map { server in
                    (server.id, try TunnelConfiguration(fromWgQuickConfig: server.config, called: server.name))
                }
                askVersions(entries, sourceVC: sourceVC) { choices in
                    guard let choices = choices else { completionHandler?(); return }
                    ClientUpdateCoordinator.shared.importDocument(document, manager: tunnelsManager, awgVersionChoices: choices) { error in
                        let message = error?.localizedDescription ?? "Заявка №\(document.snapshot.orderID) связана с приложением. Серверы и режим Авто будут обновляться при открытии приложения и по кнопке «Обновить»."
                        errorPresenterType.showErrorAlert(title: error == nil ? "Заявка подключена" : "Обновление конфигураций", message: message, from: sourceVC, onPresented: completionHandler)
                    }
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
            let entries = configs.enumerated().compactMap { index, config in config.map { (String(index), $0) } }
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
            askVersions(entries, sourceVC: sourceVC) { choices in
                guard let choices = choices else { completionHandler?(); return }
                for (id, config) in entries {
                    if let choice = choices[id] { config.interface.legacyAWG15 = choice }
                }
                addSelectedConfigurations()
            }
            #else
            if entries.allSatisfy({ !needsVersionChoice($0.1) }) { addSelectedConfigurations() }
            else {
                errorPresenterType.showErrorAlert(title: "Нужно уточнить версию AmneziaWG",
                    message: "Импорт отменён: этот файл не указывает версию однозначно.",
                    from: sourceVC, onPresented: completionHandler)
            }
            #endif
        }
    }
}
