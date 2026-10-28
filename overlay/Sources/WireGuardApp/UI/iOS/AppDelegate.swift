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

        let mainVC = MainViewController()
        let unified = VPN013UnifiedViewController(awg: mainVC)
        unifiedVC = unified
        window.rootViewController = unified
        window.makeKeyAndVisible()

        self.mainVC = mainVC

        #if targetEnvironment(simulator) && DEBUG
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
        guard url.isFileURL else { return false }
        unifiedVC?.importFile(url)
        return unifiedVC != nil
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
