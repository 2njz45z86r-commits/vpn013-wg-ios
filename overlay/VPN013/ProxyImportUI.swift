// SPDX-License-Identifier: MIT
import UIKit
import UniformTypeIdentifiers

final class ProxyImportViewController: UIViewController, UIDocumentPickerDelegate {
    private let kind: VPN013ConnectionKind
    private let input = UITextView()
    private let submit = UIButton(type: .system)
    private let progress = UIActivityIndicatorView(style: .medium)
    private let downloader = ProxySubscriptionDownload()
    private var initialText: String?
    private var isBusy = false
    private var previewGeneration = UUID()
    init(kind: VPN013ConnectionKind, text: String? = nil) { self.kind = kind; initialText = text; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { downloader.cancel() }
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Добавить · " + kind.title; view.backgroundColor = VPN013Theme.background
        let explanation = UILabel(); explanation.text = "Вставьте VLESS, текст подписки, HTTPS-ссылку подписки или выберите файл JSON Xray. Из JSON переносятся серверы VLESS; сторонние правила маршрутизации не переносятся. Их можно настроить в VPN013."
        explanation.numberOfLines = 0; explanation.font = .preferredFont(forTextStyle: .body); explanation.adjustsFontForContentSizeCategory = true; explanation.textColor = VPN013Theme.secondaryText
        input.font = .preferredFont(forTextStyle: .body); input.adjustsFontForContentSizeCategory = true
        input.backgroundColor = .secondarySystemBackground; input.textColor = VPN013Theme.text
        input.autocorrectionType = .no; input.autocapitalizationType = .none; input.spellCheckingType = .no; input.smartDashesType = .no; input.smartQuotesType = .no
        input.accessibilityLabel = "Своя конфигурация"; input.accessibilityIdentifier = "vpn013.proxy.import.text"
        input.text = initialText
        let paste = UIButton(type: .system); paste.setTitle("Вставить из буфера", for: .normal); paste.addTarget(self, action: #selector(pasteText), for: .touchUpInside)
        let file = UIButton(type: .system); file.setTitle("Выбрать файл", for: .normal); file.addTarget(self, action: #selector(pickFile), for: .touchUpInside)
        submit.setTitle("Проверить конфигурацию", for: .normal); submit.addTarget(self, action: #selector(validateInput), for: .touchUpInside)
        submit.accessibilityIdentifier = "vpn013.proxy.import.check"
        for button in [paste, file, submit] { button.heightAnchor.constraint(greaterThanOrEqualToConstant: 48).isActive = true; button.titleLabel?.font = .preferredFont(forTextStyle: .headline); button.titleLabel?.adjustsFontForContentSizeCategory = true; button.titleLabel?.numberOfLines = 0; button.tintColor = VPN013Theme.accent }
        progress.hidesWhenStopped = true; progress.color = VPN013Theme.accent
        let stack = UIStackView(arrangedSubviews: [explanation, input, paste, file, submit, progress]); stack.axis = .vertical; stack.spacing = 16
        let scroll = UIScrollView(); scroll.keyboardDismissMode = .interactive; scroll.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(scroll)
        stack.translatesAutoresizingMaskIntoConstraints = false; scroll.addSubview(stack)
        NSLayoutConstraint.activate([scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor), scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor), scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor), stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 20), stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20), stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20), stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -20), stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40), input.heightAnchor.constraint(equalToConstant: 190)])
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-unified") {
            input.text = "vless://00000000-0000-4000-8000-000000000001@demo.example.invalid:443?type=ws&security=tls&sni=demo.example.invalid&path=%2Fvpn#Demo%20server"
            if ProcessInfo.processInfo.arguments.contains("--vpn013-test-unified-json"), let prototype = try? ProxyProfile.fromURI(input.text, source: kind) {
                let profiles = (0..<4).map { index -> ProxyProfile in var value = prototype; value.id = UUID(); value.host = "node\(index).example.invalid"; value.name = "Country \(index)"; return value }
                var configurations: [[String: Any]] = (0..<3).map { primary in
                    let order = [primary] + profiles.indices.filter { $0 != primary }
                    let outbounds = order.enumerated().map { position, index -> [String: Any] in var value = try! profiles[index].outbound(); value["tag"] = position == 0 ? profiles[index].name : "backup-\(index)"; return value }
                    return ["remarks": profiles[primary].name, "inbounds": [], "outbounds": outbounds]
                }
                let automatic: [String: Any] = ["remarks": "Авто", "inbounds": [], "outbounds": profiles.enumerated().map { index, profile -> [String: Any] in var value = try! profile.outbound(); value["tag"] = "auto-\(index)"; return value }]
                configurations.insert(automatic, at: 0)
                input.text = String(decoding: try! JSONSerialization.data(withJSONObject: configurations, options: [.sortedKeys]), as: UTF8.self)
            }
        }
        #endif
    }
    @objc private func pasteText() {
        guard !isBusy else { return }
        guard let value = UIPasteboard.general.string else { show(ProxyProfileError.invalid); return }
        guard value.utf8.count <= ProxyImport.maximumBytes else { show(ProxyProfileError.tooLarge); return }
        input.text = value
    }
    @objc private func pickFile() {
        guard !isBusy else { return }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.plainText, .json, .data], asCopy: false)
        picker.delegate = self; picker.allowsMultipleSelection = false; present(picker, animated: true)
    }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) { if let url = urls.first { readFile(url) } }
    func readFile(_ url: URL) {
        loadViewIfNeeded()
        let scoped = url.startAccessingSecurityScopedResource(); defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            guard url.isFileURL else { throw ProxyProfileError.invalid }
            let file = try FileHandle(forReadingFrom: url); defer { try? file.close() }
            let data = try file.read(upToCount: ProxyImport.maximumBytes + 1) ?? Data()
            guard data.count <= ProxyImport.maximumBytes else { throw ProxyProfileError.tooLarge }
            guard let text = String(data: data, encoding: .utf8) else { throw ProxyProfileError.invalid }
            if data.count > 131_072 { input.text = ""; preview(data) }
            else { input.text = text }
        } catch { show(error is ProxyProfileError ? error : ProxyProfileError.invalid) }
    }
    @objc private func validateInput() {
        guard !isBusy else { return }
        view.endEditing(true)
        let text = (input.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.utf8.count <= ProxyImport.maximumBytes else { show(ProxyProfileError.tooLarge); return }
        if let url = URL(string: text), url.scheme?.lowercased() == "https" {
            guard VPN013SubscriptionRequest.isSecure(url) else { show(ProxyProfileError.invalid); return }
            let alert = UIAlertController(title: "Загрузить подписку?", message: "VPN013 запросит конфигурации у \(url.host ?? "сервиса") и передаст постоянный случайный идентификатор этой установки для данного сервиса — для проверки привязки устройства. У других VPN-приложений свои идентификаторы. Для привязанной к ним ссылки может понадобиться отдельное устройство в кабинете провайдера.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Загрузить", style: .default) { [weak self] _ in
                guard let self = self else { return }; self.busy(true)
                let identity: String
                do { identity = try VPN013SubscriptionIdentity.identifier(for: url.host!, directory: PrivateTunnelStore.defaultDirectory) }
                catch { self.busy(false); self.show(ProxySubscriptionError.identity); return }
                self.downloader.start(url, kind: self.kind, identifier: identity) { [weak self] result in
                    guard let self = self else { return }; self.busy(false)
                    switch result {
                    case .success(let data): self.preview(data)
                    case .failure(let error): self.show(error)
                    }
                }
            }); alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true)
        } else { preview(Data(text.utf8)) }
    }
    private func preview(_ data: Data) {
        let generation = UUID(); previewGeneration = generation; let source = kind
        busy(true)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try ProxyImport.profiles(data, source: source) }
            DispatchQueue.main.async {
            guard let self = self, self.previewGeneration == generation else { return }
            self.busy(false)
            guard self.viewIfLoaded?.window != nil else { return }
            switch result {
            case .success(let values): self.showPreview(values)
            case .failure(let error): self.show(error is ProxyProfileError ? error : ProxyProfileError.invalid)
            }
            }
        }
    }
    private func showPreview(_ values: [ProxyProfile]) {
            let names = values.prefix(8).map { $0.name }.joined(separator: "\n")
            let alert = UIAlertController(title: "Серверов: \(values.count)", message: names + (values.count > 8 ? "\n…" : "") + "\n\nДобавить в раздел \(kind.title)?", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Добавить", style: .default) { [weak self] _ in
                guard let self = self else { return }; self.busy(true)
                ProxyProfilesManager.shared.add(values) { [weak self] error in
                    guard let self = self else { return }; self.busy(false)
                    if let error = error { self.show(error) } else { self.input.text = ""; self.navigationController?.popToRootViewController(animated: true) }
                }
            }); alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true)
    }
    private func busy(_ value: Bool) { isBusy = value; submit.isEnabled = !value; input.isEditable = !value; value ? progress.startAnimating() : progress.stopAnimating() }
    private func show(_ error: Error) {
        let alert = UIAlertController(title: "Не удалось добавить", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}
