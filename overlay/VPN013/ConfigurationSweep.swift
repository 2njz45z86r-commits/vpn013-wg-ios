// SPDX-License-Identifier: MIT
import UIKit
import NetworkExtension

/// One row of a sweep: a configuration the person already has, tested by a
/// real VPN start. Nothing is created, edited or deleted.
struct ConfigurationSweepResult {
    enum Outcome { case pending, running, traffic, connectedNoTraffic, notConnected, skipped }
    let section: String
    let name: String
    var outcome: Outcome = .pending
    var detail = ""
    var text: String {
        switch outcome {
        case .pending: return "ожидает"
        case .running: return "проверяем…"
        case .traffic: return "трафик есть · " + detail
        case .connectedNoTraffic: return "подключено, трафика нет" + (detail.isEmpty ? "" : " · " + detail)
        case .notConnected: return "не подключилось" + (detail.isEmpty ? "" : " · " + detail)
        case .skipped: return "пропущено" + (detail.isEmpty ? "" : " · " + detail)
        }
    }
}

/// Real end-to-end check of every saved configuration, one at a time:
/// start the VPN, fetch the exit address and 1 MB through it, stop it.
/// The screen stays awake; iOS suspends apps in the background, so the
/// sweep pauses there and the person is told to keep the app open.
final class ConfigurationSweepViewController: UITableViewController {
    private let tunnels: TunnelsManager
    private let proxies = ProxyProfilesManager.shared
    private var results: [ConfigurationSweepResult] = []
    private var jobs: [() -> Job] = []
    private var running = false
    private var cancelled = false
    private var savedReporter: ((Error) -> Void)?
    private var lastProxyError: Error?
    private let status = UILabel()
    private var startButton: UIBarButtonItem!

    private struct Job {
        let start: () -> Void
        let stop: () -> Void
        let connected: () -> Bool
        let stopped: () -> Bool
    }

    init(tunnels: TunnelsManager) { self.tunnels = tunnels; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad(); title = "Проверка конфигураций"
        tableView.backgroundColor = VPN013Theme.background
        startButton = UIBarButtonItem(title: "Начать", style: .done, target: self, action: #selector(startTapped))
        startButton.accessibilityIdentifier = "vpn013.sweep.start"
        navigationItem.rightBarButtonItem = startButton
        status.numberOfLines = 0; status.font = .preferredFont(forTextStyle: .footnote); status.adjustsFontForContentSizeCategory = true
        status.textColor = VPN013Theme.secondaryText; status.accessibilityIdentifier = "vpn013.sweep.status"
        status.text = "Каждая конфигурация по очереди включается, через неё загружаются адрес выхода и 1 МБ, затем она выключается. Держите приложение открытым: в фоне iOS приостанавливает проверку. Перед началом выключите VPN."
        let header = UIView(); status.translatesAutoresizingMaskIntoConstraints = false; header.addSubview(status)
        NSLayoutConstraint.activate([status.leadingAnchor.constraint(equalTo: header.layoutMarginsGuide.leadingAnchor), status.trailingAnchor.constraint(equalTo: header.layoutMarginsGuide.trailingAnchor), status.topAnchor.constraint(equalTo: header.topAnchor, constant: 12), status.bottomAnchor.constraint(equalTo: header.bottomAnchor, constant: -8)])
        tableView.tableHeaderView = header
        build()
    }
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews(); guard let header = tableView.tableHeaderView else { return }
        let height = header.systemLayoutSizeFitting(CGSize(width: tableView.bounds.width, height: UIView.layoutFittingCompressedSize.height), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel).height
        if abs(header.frame.height - height) > 0.5 { header.frame.size = CGSize(width: tableView.bounds.width, height: height); tableView.tableHeaderView = header }
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if isMovingFromParent || isBeingDismissed || navigationController?.isBeingDismissed == true { cancelled = true }
    }

    /// Snapshot the configurations now; later list changes do not alter a running sweep.
    private func build() {
        results = []; jobs = []
        for index in 0..<tunnels.numberOfTunnels() {
            let tunnel = tunnels.tunnel(at: index)
            guard !tunnel.isVPN013Automatic else { continue }
            results.append(ConfigurationSweepResult(section: "AmneziaWG", name: tunnel.name))
            jobs.append { [weak self] in Job(
                start: { self?.tunnels.startActivation(of: tunnel) },
                stop: { self?.tunnels.startDeactivation(of: tunnel) },
                connected: { tunnel.status == .active },
                stopped: { tunnel.status == .inactive }) }
        }
        for kind in VPN013ConnectionKind.allCases where kind != .amneziawg {
            for entry in proxies.entries where entry.value.profile.source == kind {
                let id = entry.value.profile.id
                results.append(ConfigurationSweepResult(section: kind.title, name: entry.value.profile.name))
                jobs.append { [weak self] in
                    func current() -> ProxyProfilesManager.Entry? { self?.proxies.entries.first { $0.value.profile.id == id } }
                    return Job(
                        start: { if let entry = current(), !entry.inOperation { self?.proxies.toggle(entry) } },
                        stop: { if let entry = current(), entry.inOperation { self?.proxies.toggle(entry) } },
                        connected: { current()?.status == .connected },
                        stopped: { current().map { !$0.inOperation } ?? true })
                }
            }
        }
        tableView.reloadData()
    }

    @objc private func startTapped() {
        if running { cancelled = true; status.text = "Останавливаем после текущей конфигурации…"; return }
        guard tunnels.tunnelInOperation() == nil, !proxies.entries.contains(where: { $0.inOperation }) else {
            alert("Сначала выключите VPN", "Проверка включает конфигурации по очереди и не может начаться, пока работает подключение."); return
        }
        guard !jobs.isEmpty else { alert("Нет конфигураций", "Добавьте конфигурации, чтобы их проверить."); return }
        build(); running = true; cancelled = false
        startButton.title = "Остановить"
        UIApplication.shared.isIdleTimerDisabled = true
        // Collect proxy start errors into the row instead of a stack of alerts.
        savedReporter = proxies.reportError
        proxies.reportError = { [weak self] error in self?.lastProxyError = error }
        run(0)
    }

    private func finish() {
        running = false; UIApplication.shared.isIdleTimerDisabled = false
        proxies.reportError = savedReporter; savedReporter = nil
        startButton.title = "Начать"
        let ok = results.filter { $0.outcome == .traffic }.count
        status.text = (cancelled ? "Проверка остановлена. " : "Проверка завершена. ") + "Трафик есть: \(ok) из \(results.count). Отчёт можно отправить кнопкой ниже."
        navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Отправить отчёт", style: .plain, target: self, action: #selector(shareReport))
        navigationItem.leftBarButtonItem?.accessibilityIdentifier = "vpn013.sweep.share"
        tableView.reloadData(); viewDidLayoutSubviews()
    }

    private func run(_ index: Int) {
        guard index < jobs.count, !cancelled else { finish(); return }
        let job = jobs[index]()
        results[index].outcome = .running; lastProxyError = nil
        status.text = "Проверяем \(index + 1) из \(jobs.count): \(results[index].section) · \(results[index].name)"
        reload(index)
        job.start()
        wait(until: job.connected, seconds: 25) { [weak self] connected in
            guard let self = self else { return }
            guard connected else {
                self.results[index].outcome = .notConnected
                self.results[index].detail = self.lastProxyError.map { _ in "система не запустила VPN" } ?? "нет подключения за 25 с"
                self.stopThenNext(job, index); return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                Self.measure { result in
                    switch result {
                    case .success(let value): self.results[index].outcome = .traffic; self.results[index].detail = value
                    case .failure: self.results[index].outcome = .connectedNoTraffic
                    }
                    self.stopThenNext(job, index)
                }
            }
        }
    }
    private func stopThenNext(_ job: Job, _ index: Int) {
        reload(index); job.stop()
        wait(until: job.stopped, seconds: 15) { [weak self] _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self?.run(index + 1) }
        }
    }
    private func wait(until condition: @escaping () -> Bool, seconds: Double, done: @escaping (Bool) -> Void) {
        let deadline = Date().addingTimeInterval(seconds)
        func poll() {
            if condition() { done(true); return }
            if Date() >= deadline || cancelled { done(false); return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: poll)
        }
        poll()
    }

    /// Exit address and 1 MB through the active tunnel; no cookies or cache.
    private static func measure(completion: @escaping (Result<String, Error>) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 12; configuration.timeoutIntervalForResource = 20
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: configuration)
        let started = Date()
        session.dataTask(with: URL(string: "https://api.ipify.org")!) { data, response, error in
            let ip = data.flatMap { String(data: $0, encoding: .utf8) }?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard error == nil, (response as? HTTPURLResponse)?.statusCode == 200,
                  ip.range(of: "^[0-9a-fA-F:.]{3,45}$", options: .regularExpression) != nil else {
                session.invalidateAndCancel(); DispatchQueue.main.async { completion(.failure(URLError(.cannotLoadFromNetwork))) }; return
            }
            let latency = Int(Date().timeIntervalSince(started) * 1000)
            let downloadStart = Date()
            session.dataTask(with: URL(string: "https://speed.cloudflare.com/__down?bytes=1000000")!) { body, reply, failure in
                session.finishTasksAndInvalidate()
                var text = "IP \(ip) · ответ \(latency) мс"
                if failure == nil, (reply as? HTTPURLResponse)?.statusCode == 200, let body = body, body.count >= 900_000 {
                    let seconds = max(0.001, Date().timeIntervalSince(downloadStart))
                    text += String(format: " · %.1f Мбит/с", Double(body.count) * 8 / seconds / 1_000_000)
                } else { text += " · загрузка 1 МБ не прошла" }
                DispatchQueue.main.async { completion(.success(text)) }
            }.resume()
        }.resume()
    }

    private func reload(_ index: Int) {
        let path = IndexPath(row: index, section: 0)
        if tableView.numberOfRows(inSection: 0) > index { tableView.reloadRows(at: [path], with: .none) }
    }
    private func alert(_ title: String, _ message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
    @objc private func shareReport() {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let lines = results.map { "\($0.section) · \($0.name): \($0.text)" }
        let report = (["Проверка конфигураций VPN013 \(version) · " + DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .short)] + lines).joined(separator: "\n")
        let share = UIActivityViewController(activityItems: [report], applicationActivities: nil)
        share.popoverPresentationController?.barButtonItem = navigationItem.leftBarButtonItem
        present(share, animated: true)
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { max(1, results.count) }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.background; cell.selectionStyle = .none
        cell.textLabel?.textColor = VPN013Theme.text; cell.detailTextLabel?.textColor = VPN013Theme.secondaryText
        cell.textLabel?.numberOfLines = 0; cell.detailTextLabel?.numberOfLines = 0
        guard results.indices.contains(indexPath.row) else { cell.textLabel?.text = "Нет конфигураций для проверки"; return cell }
        let result = results[indexPath.row]
        cell.textLabel?.text = result.section + " · " + result.name
        cell.detailTextLabel?.text = result.text
        cell.accessibilityIdentifier = "vpn013.sweep.row"
        let symbol: String
        switch result.outcome {
        case .traffic: symbol = "checkmark.circle.fill"; cell.imageView?.tintColor = .systemGreen
        case .connectedNoTraffic: symbol = "exclamationmark.triangle.fill"; cell.imageView?.tintColor = .systemOrange
        case .notConnected: symbol = "xmark.circle.fill"; cell.imageView?.tintColor = .systemRed
        case .running: symbol = "arrow.triangle.2.circlepath"; cell.imageView?.tintColor = VPN013Theme.accent
        default: symbol = "circle"; cell.imageView?.tintColor = VPN013Theme.secondaryText
        }
        cell.imageView?.image = UIImage(systemName: symbol)
        return cell
    }
}
