// SPDX-License-Identifier: MIT
import UIKit
import NetworkExtension

extension TunnelsListTableViewController {
    @objc func automaticTapped() {
        guard let manager = tunnelsManager else { return }
        let all = manager.mapTunnels { $0 }
        guard !all.contains(where: { $0.status != .inactive }) else { showAutomaticError(AutoTunnelError.active); return }
        let manual = all.filter { !$0.isVPN013Automatic }
        guard !manual.isEmpty, manual.allSatisfy({ $0.tunnelConfiguration != nil }) else {
            showAutomaticError(AutoTunnelError.invalidGroup); return
        }
        let configs = manual.compactMap { $0.tunnelConfiguration }
        do { _ = try AutoTunnelProfile(configurations: configs) } catch { showAutomaticError(error); return }
        let names = configs.compactMap { $0.name }.joined(separator: ", ")
        let countLabel = AutoTunnelProfile.serverCountLabel(configs.count)
        let explanation = configs.count == 1 ? "Сейчас доступен один сервер. Для переключения на резерв добавьте ещё серверы и создайте Авто заново." : "При потере трафика приложение проверит остальные серверы по очереди."
        let alert = UIAlertController(title: "Создать режим Авто", message: "В режиме Авто: " + countLabel + ".\n\n" + names + "\n\n" + explanation + " Ключи сохраняются. Ручное выключение останавливает переключение. Авто хранит отдельную копию подключений: после добавления, изменения или удаления исходных серверов создайте его заново.", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Создать Авто", style: .default) { [weak self] _ in
            guard let self = self else { return }
            let create = {
                do {
                    let profile = try AutoTunnelProfile(configurations: configs)
                    let primary = configs[0]
                    let config = TunnelConfiguration(name: "Авто · " + countLabel, interface: primary.interface, peers: primary.peers)
                    manager.add(tunnelConfiguration: config, automaticProfile: profile) { [weak self] result in
                        switch result {
                        case .success(let tunnel):
                            ClientUpdateCoordinator.shared.rememberAuto(tunnel, sources: manual)
                            self?.showTunnelDetail(for: tunnel, animated: true)
                        case .failure(let error): self?.showAutomaticError(error)
                        }
                    }
                } catch { self.showAutomaticError(error) }
            }
            if let old = all.first(where: { $0.isVPN013Automatic }) {
                manager.remove(tunnel: old) { error in if let error = error { self.showAutomaticError(error) } else { create() } }
            } else { create() }
        })
        alert.addAction(UIAlertAction(title: "Отмена", style: .cancel))
        present(alert, animated: true)
    }
    private func showAutomaticError(_ error: Error) {
        let alert = UIAlertController(title: "Авто не создано", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}
