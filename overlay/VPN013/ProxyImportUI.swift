// SPDX-License-Identifier: MIT
import UIKit
import UniformTypeIdentifiers
import AVFoundation

final class ProxyImportViewController: UIViewController, UIDocumentPickerDelegate {
    private let kind: VPN013ConnectionKind
    private let input = UITextView()
    private let submit = UIButton(type: .system)
    private let paste = UIButton(type: .system)
    private let file = UIButton(type: .system)
    private let qr = UIButton(type: .system)
    private let progress = UIActivityIndicatorView(style: .medium)
    private let downloader = ProxySubscriptionDownload()
    private var initialText: String?
    private var isBusy = false
    private var previewGeneration = UUID()
    init(kind: VPN013ConnectionKind, text: String? = nil) { self.kind = kind; initialText = text; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { downloader.cancel() }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if isMovingFromParent || navigationController?.isBeingDismissed == true {
            downloader.cancel(); previewGeneration = UUID()
        }
    }
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Добавить · " + kind.title; view.backgroundColor = VPN013Theme.background
        let settings = UIBarButtonItem(image: UIImage(systemName: "gearshape"), style: .plain, target: self, action: #selector(openSettings))
        settings.accessibilityLabel = "Настройки"; settings.accessibilityIdentifier = "vpn013.settings"
        navigationItem.rightBarButtonItem = settings
        let explanation = UILabel(); explanation.text = "Вставьте ключ или ссылку подписки. VPN013 определит формат."
        explanation.numberOfLines = 0; explanation.font = .preferredFont(forTextStyle: .body); explanation.adjustsFontForContentSizeCategory = true; explanation.textColor = VPN013Theme.secondaryText
        input.font = .preferredFont(forTextStyle: .body); input.adjustsFontForContentSizeCategory = true
        input.backgroundColor = .secondarySystemBackground; input.textColor = VPN013Theme.text
        input.autocorrectionType = .no; input.autocapitalizationType = .none; input.spellCheckingType = .no; input.smartDashesType = .no; input.smartQuotesType = .no
        input.accessibilityLabel = "Своя конфигурация"; input.accessibilityIdentifier = "vpn013.proxy.import.text"
        input.text = initialText
        let keyboardBar = UIToolbar(); keyboardBar.sizeToFit()
        keyboardBar.items = [UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil), UIBarButtonItem(title: "Готово", style: .done, target: self, action: #selector(hideKeyboard))]
        input.inputAccessoryView = keyboardBar
        paste.setTitle("Из буфера", for: .normal); paste.addTarget(self, action: #selector(pasteText), for: .touchUpInside)
        paste.accessibilityIdentifier = "vpn013.proxy.import.paste"
        file.setTitle("Выбрать файл", for: .normal); file.addTarget(self, action: #selector(pickFile), for: .touchUpInside)
        qr.setTitle("QR-код", for: .normal); qr.addTarget(self, action: #selector(scanQR), for: .touchUpInside)
        qr.accessibilityIdentifier = "vpn013.proxy.import.qr"
        submit.setTitle("Загрузить конфигурацию", for: .normal); submit.addTarget(self, action: #selector(validateInput), for: .touchUpInside)
        submit.accessibilityIdentifier = "vpn013.proxy.import.check"
        for button in [paste, qr, file, submit] { button.heightAnchor.constraint(greaterThanOrEqualToConstant: 48).isActive = true; button.titleLabel?.font = .preferredFont(forTextStyle: .headline); button.titleLabel?.adjustsFontForContentSizeCategory = true; button.titleLabel?.numberOfLines = 0; button.tintColor = VPN013Theme.accent }
        progress.hidesWhenStopped = true; progress.color = VPN013Theme.accent
        let actions = UIStackView(arrangedSubviews: [paste, qr, file]); actions.axis = .horizontal; actions.distribution = .fillEqually; actions.spacing = 12
        paste.backgroundColor = VPN013Theme.accent; paste.setTitleColor(VPN013Theme.background, for: .normal); paste.layer.cornerRadius = 12
        input.layer.cornerRadius = 12; input.textContainerInset = UIEdgeInsets(top: 12, left: 10, bottom: 12, right: 10)
        let privacy = UILabel(); privacy.text = "При загрузке подписки сервис получает случайный идентификатор этой установки VPN013."
        privacy.numberOfLines = 0; privacy.font = .preferredFont(forTextStyle: .footnote); privacy.adjustsFontForContentSizeCategory = true; privacy.textColor = VPN013Theme.secondaryText
        let stack = UIStackView(arrangedSubviews: [explanation, actions, input, submit, progress, privacy]); stack.axis = .vertical; stack.spacing = 16
        let scroll = UIScrollView(); scroll.keyboardDismissMode = .interactive; scroll.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(scroll)
        stack.translatesAutoresizingMaskIntoConstraints = false; scroll.addSubview(stack)
        let keyboardBottom: NSLayoutYAxisAnchor
        if #available(iOS 15, *) { keyboardBottom = view.keyboardLayoutGuide.topAnchor }
        else { keyboardBottom = view.safeAreaLayoutGuide.bottomAnchor }
        NSLayoutConstraint.activate([scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor), scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor), scroll.bottomAnchor.constraint(equalTo: keyboardBottom), stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 20), stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20), stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20), stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -20), stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40), input.heightAnchor.constraint(equalToConstant: 132)])
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-unified") {
            input.text = "vless://00000000-0000-4000-8000-000000000001@demo.example.invalid:443?type=ws&security=tls&sni=demo.example.invalid&path=%2Fvpn#Demo%20server"
            if ProcessInfo.processInfo.arguments.contains("--vpn013-test-unified-json"), let prototype = try? ProxyProfile.fromURI(input.text, source: kind) {
                do {
                let profiles = (0..<4).map { index -> ProxyProfile in var value = prototype; value.id = UUID(); value.host = "node\(index).example.invalid"; value.name = "Country \(index)"; return value }
                var configurations: [[String: Any]] = try (0..<3).map { primary in
                    let order = [primary] + profiles.indices.filter { $0 != primary }
                    let outbounds = try order.enumerated().map { position, index -> [String: Any] in var value = try profiles[index].outbound(); value["tag"] = position == 0 ? profiles[index].name : "backup-\(index)"; return value }
                    return ["remarks": profiles[primary].name, "inbounds": [], "outbounds": outbounds]
                }
                let automatic: [String: Any] = ["remarks": "Авто", "inbounds": [], "outbounds": try profiles.enumerated().map { index, profile -> [String: Any] in var value = try profile.outbound(); value["tag"] = "auto-\(index)"; return value }]
                configurations.insert(automatic, at: 0)
                input.text = String(decoding: try JSONSerialization.data(withJSONObject: configurations, options: [.sortedKeys]), as: UTF8.self)
                } catch { input.text = "invalid synthetic fixture" }
            }
        }
        #endif
    }
    @objc private func pasteText() {
        guard !isBusy else { return }
        guard let value = UIPasteboard.general.string else { show(ProxyProfileError.invalid); return }
        guard value.utf8.count <= ProxyImport.maximumBytes else { show(ProxyProfileError.tooLarge); return }
        input.text = value
        view.endEditing(true)
    }
    func offerIncomingText(_ text: String?) {
        guard let text = text, !isBusy else { return }; loadViewIfNeeded()
        if (input.text ?? "").isEmpty { input.text = text; return }
        guard presentedViewController == nil else { return }
        let alert = UIAlertController(title: "Заменить введённый ключ?", message: "Открыта новая ссылка из бота. Текущий текст будет заменён только после подтверждения.", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Заменить", style: .default) { [weak self] _ in self?.input.text = text })
        alert.addAction(UIAlertAction(title: "Оставить текущий", style: .cancel)); present(alert, animated: true)
    }
    @objc private func hideKeyboard() { view.endEditing(true) }
    @objc private func scanQR() {
        guard !isBusy else { return }; view.endEditing(true)
        let scanner = VPN013QRImportController()
        scanner.received = { [weak self] text in
            guard let self = self, !self.isBusy else { return }
            self.input.text = text
        }
        present(UINavigationController(rootViewController: scanner), animated: true)
    }
    @objc private func pickFile() {
        guard !isBusy else { return }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.plainText, .json, .zip, .data], asCopy: false)
        picker.delegate = self; picker.allowsMultipleSelection = false; present(picker, animated: true)
    }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) { if let url = urls.first { readFile(url) } }
    func readFile(_ url: URL) {
        loadViewIfNeeded()
        let scoped = url.startAccessingSecurityScopedResource(); defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            guard url.isFileURL else { throw ProxyProfileError.invalid }
            if url.pathExtension.lowercased() == "zip" {
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                guard let size = attributes[.size] as? NSNumber, size.int64Value <= Int64(ProxyImport.maximumBytes) else { throw ProxyProfileError.tooLarge }
                // Owner archives contain equivalent Android/iPhone copies. Import
                // only a unique subscription, never an arbitrary instruction file.
                let entries = try ZipArchive.unarchive(url: url, requiredFileExtensions: ["txt"])
                let subscriptions = entries.filter { $0.fileBaseName == "Подписка" }.map { $0.contents }
                guard let data = subscriptions.first, subscriptions.allSatisfy({ $0 == data }),
                      let text = String(data: data, encoding: .utf8) else { throw ProxyProfileError.invalid }
                input.text = text; validateInput(); return
            }
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
        let text: String
        do { text = try VPN013SubscriptionRequest.importText(input.text ?? "") }
        catch { show(error); return }
        guard text.utf8.count <= ProxyImport.maximumBytes else { show(ProxyProfileError.tooLarge); return }
        if let url = URL(string: text), url.scheme?.lowercased() == "https" {
            guard VPN013SubscriptionRequest.isSecure(url) else { show(ProxyProfileError.invalid); return }
            self.busy(true)
                let identity: String
                do { identity = try VPN013SubscriptionIdentity.identifier(for: url.host!, directory: PrivateTunnelStore.defaultDirectory) }
                catch { self.busy(false); self.show(ProxySubscriptionError.identity); return }
                self.downloader.start(url, kind: self.kind, identifier: identity) { [weak self] result in
                    guard let self = self else { return }; self.busy(false)
                    switch result {
                    case .success(let data): self.preview(data, subscriptionURL: url)
                    case .failure(let error): self.show(error)
                    }
                }
        } else { preview(Data(text.utf8)) }
    }
    private func preview(_ data: Data, subscriptionURL: URL? = nil) {
        let generation = UUID(); previewGeneration = generation; let source = kind
        busy(true)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try ProxyImport.profiles(data, source: source) }
            DispatchQueue.main.async {
            guard let self = self, self.previewGeneration == generation else { return }
            self.busy(false)
            guard self.viewIfLoaded?.window != nil else { return }
            switch result {
            case .success(let values): self.showPreview(values, subscriptionURL: subscriptionURL)
            case .failure(let error): self.show(error is ProxyProfileError ? error : ProxyProfileError.invalid)
            }
            }
        }
    }
    private func showPreview(_ values: [ProxyProfile], subscriptionURL: URL?) {
            let names = values.prefix(8).map { $0.name }.joined(separator: "\n")
            let note = subscriptionURL == nil ? "" : "\nИсточник будет сохранён защищённо. Потяните список вниз для обновления серверов этой подписки."
            let alert = UIAlertController(title: "Серверов: \(values.count)", message: names + (values.count > 8 ? "\n…" : "") + "\n\nДобавить в раздел \(kind.title)?" + note, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Добавить", style: .default) { [weak self] _ in
                guard let self = self else { return }; self.busy(true)
                let done: (Error?) -> Void = { [weak self] error in
                    guard let self = self else { return }; self.busy(false)
                    if let error = error { self.show(error) } else { self.input.text = ""; self.navigationController?.popToRootViewController(animated: true) }
                }
                if let url = subscriptionURL { ProxyProfilesManager.shared.installSubscription(url, profiles: values, kind: self.kind, completion: done) }
                else { ProxyProfilesManager.shared.add(values, completion: done) }
            }); alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true)
    }
    @objc private func openSettings() { guard !isBusy else { return }; VPN013SettingsPresentation.show(from: self, kind: kind) }
    private func busy(_ value: Bool) { isBusy = value; navigationItem.rightBarButtonItem?.isEnabled = !value; submit.isEnabled = !value; qr.isEnabled = !value; paste.isEnabled = !value; file.isEnabled = !value; input.isEditable = !value; value ? progress.startAnimating() : progress.stopAnimating() }
    private func show(_ error: Error) {
        let alert = UIAlertController(title: "Не удалось добавить", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}

/// Captures only QR text after an explicit tap. No images or decoded keys are logged or persisted.
private final class VPN013QRImportController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var received: ((String) -> Void)?
    private let capture = AVCaptureSession()
    private let queue = DispatchQueue(label: "VPN013.QR.capture")
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var consumed = false
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Сканировать QR-код"; view.backgroundColor = .black
        navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Отмена", style: .plain, target: self, action: #selector(cancel))
        AVCaptureDevice.requestAccess(for: .video) { [weak self] allowed in
            DispatchQueue.main.async {
                guard let self = self, self.view.window != nil else { return }
                guard allowed else { self.unavailable(); return }
                self.configure()
            }
        }
    }
    private func configure() {
        guard let camera = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: camera), capture.canAddInput(input) else { unavailable(); return }
        capture.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard capture.canAddOutput(output) else { unavailable(); return }
        capture.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: capture); layer.videoGravity = .resizeAspectFill
        view.layer.insertSublayer(layer, at: 0); previewLayer = layer; layer.frame = view.bounds
        queue.async { [capture] in capture.startRunning() }
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); previewLayer?.frame = view.bounds }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated); queue.async { [capture] in capture.stopRunning() }
    }
    @objc private func cancel() { dismiss(animated: true) }
    private func unavailable() {
        let alert = UIAlertController(title: "Камера недоступна", message: "Разрешите камеру в настройках iPhone или добавьте ключ из буфера либо файла.", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default) { [weak self] _ in self?.dismiss(animated: true) }); present(alert, animated: true)
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !consumed, let text = objects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first,
              text.utf8.count <= ProxyImport.maximumBytes else { return }
        consumed = true; let handler = received
        dismiss(animated: true) { handler?(text) }
    }
}
