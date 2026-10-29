// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import UIKit
import os.log

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    var mainVC: MainViewController?
    var unifiedVC: VPN013UnifiedViewController?
    var isLaunchedForSpecificAction = false

    func application(_ application: UIApplication, willFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        Logger.configureGlobal(tagged: "APP", withFilePath: FileManager.logFileURL?.path)
        _ = NativeTrialCoordinator.shared

        if let launchOptions = launchOptions {
            if launchOptions[.url] != nil || launchOptions[.shortcutItem] != nil {
                isLaunchedForSpecificAction = true
            }
        }

        let window = UIWindow(frame: UIScreen.main.bounds)
        // The owner selected the night palette; keep system sheets and details
        // in the same appearance while preserving native navigation and controls.
        window.overrideUserInterfaceStyle = .dark
        window.tintColor = VPN013Theme.accent
        let navigation = VPN013Theme.navigationAppearance()
        UINavigationBar.appearance().standardAppearance = navigation
        UINavigationBar.appearance().scrollEdgeAppearance = navigation
        UINavigationBar.appearance().compactAppearance = navigation
        UINavigationBar.appearance().tintColor = VPN013Theme.accent
        UITableView.appearance().backgroundColor = VPN013Theme.background
        UITableView.appearance().separatorColor = VPN013Theme.separator
        UITableViewCell.appearance().backgroundColor = VPN013Theme.background
        self.window = window

        #if targetEnvironment(simulator) && DEBUG
        // Initialize before any header reads preferences. Legacy native tests
        // explicitly use manual mode; the dedicated Auto test checks defaults.
        let args = ProcessInfo.processInfo.arguments
        if args.contains("--vpn013-test-auto-reset") { UserDefaults.standard.removeObject(forKey: VPN013AutomaticMode.preferenceKey) }
        else if !args.contains("--vpn013-test-automatic"), args.contains(where: { $0.hasPrefix("--vpn013-test-") }) { VPN013AutomaticMode.setEnabled(false) }
        #endif
        let mainVC = MainViewController()
        let unified = VPN013UnifiedViewController(awg: mainVC)
        unifiedVC = unified
        window.rootViewController = unified
        window.makeKeyAndVisible()

        self.mainVC = mainVC

        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-owner-proxy-zip") {
            do {
                let fixture = FileManager.default.temporaryDirectory.appendingPathComponent("vpn013-proxy-fixture-" + UUID().uuidString + ".zip")
                let subscription = Data("vless://00000000-0000-4000-8000-000000000001@server.example.org:443?type=tcp&security=tls#Example\n".utf8)
                let entries: [(fileName: String, contents: Data)] = [
                    ("iPhone/Подписка.txt", subscription), ("Android/Подписка.txt", subscription),
                    ("iPhone/Инструкция.txt", Data("Тест · INCY · iPhone\n".utf8)),
                    ("Android/Инструкция.txt", Data("Тест · INCY · Android\n".utf8))]
                try ZipArchive.archive(inputs: entries, to: fixture)
                DispatchQueue.main.async { _ = self.application(application, open: fixture) }
            } catch { wg_log(.error, message: "Unable to prepare local proxy ZIP fixture") }
        }
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-import") {
            // Exercise the same incoming-file handler as iOS Open In / Share.
            do {
                let fixture = try MockTunnels.sharedArchiveFixture()
                DispatchQueue.main.async { _ = self.application(application, open: fixture) }
            } catch {
                wg_log(.error, message: "Unable to prepare local simulator import fixture")
            }
        }
        #endif

        return true
    }

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        guard let unified = unifiedVC else { return false }
        if url.isFileURL { unified.importFile(url); return true }
        guard url.scheme?.lowercased() == "vpn013" else { return false }
        do {
            let handoff = try VPN013ImportLink.parse(url)
            DispatchQueue.main.async { unified.importConnection(kind: handoff.kind, text: handoff.text) }
            return true
        } catch { return false }
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        unifiedVC?.foreground()
    }

    func applicationWillResignActive(_ application: UIApplication) {
        guard let allTunnelNames = mainVC?.allTunnelNames() else { return }
        application.shortcutItems = QuickActionItem.createItems(allTunnelNames: allTunnelNames)
    }

    func application(_ application: UIApplication, performActionFor shortcutItem: UIApplicationShortcutItem, completionHandler: @escaping (Bool) -> Void) {
        guard shortcutItem.type == QuickActionItem.type else {
            completionHandler(false)
            return
        }
        let tunnelName = shortcutItem.localizedTitle
        mainVC?.showTunnelDetailForTunnel(named: tunnelName, animated: false, shouldToggleStatus: true)
        completionHandler(true)
    }
}

extension AppDelegate {
    func application(_ application: UIApplication, shouldSaveApplicationState coder: NSCoder) -> Bool {
        return true
    }

    func application(_ application: UIApplication, shouldRestoreApplicationState coder: NSCoder) -> Bool {
        return !self.isLaunchedForSpecificAction
    }

    func application(_ application: UIApplication, viewControllerWithRestorationIdentifierPath identifierComponents: [String], coder: NSCoder) -> UIViewController? {
        guard let vcIdentifier = identifierComponents.last else { return nil }
        if vcIdentifier.hasPrefix("TunnelDetailVC:") {
            let tunnelName = String(vcIdentifier.suffix(vcIdentifier.count - "TunnelDetailVC:".count))
            if let tunnelsManager = mainVC?.tunnelsManager {
                if let tunnel = tunnelsManager.tunnel(named: tunnelName) {
                    return TunnelDetailTableViewController(tunnelsManager: tunnelsManager, tunnel: tunnel)
                }
            } else {
                // Show it when tunnelsManager is available
                mainVC?.showTunnelDetailForTunnel(named: tunnelName, animated: false, shouldToggleStatus: false)
            }
        }
        return nil
    }
}
