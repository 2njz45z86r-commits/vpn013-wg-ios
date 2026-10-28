// SPDX-License-Identifier: MIT
import UIKit
import UniformTypeIdentifiers

final class ProxySubscriptionDownload: NSObject, URLSessionDataDelegate {
    private var session: URLSession?
    private var received = Data()
    private var original: URL?
    private var completion: ((Data?) -> Void)?
    func start(_ url: URL, completion: @escaping (Data?) -> Void) {
        cancel()
        guard url.scheme?.lowercased() == "https", url.host != nil, url.user == nil, url.password == nil else { completion(nil); return }
        original = url; self.completion = completion; received = Data()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 25
        config.httpCookieStorage = nil; config.httpShouldSetCookies = false; config.urlCredentialStorage = nil; config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: config, delegate: self, delegateQueue: .main); self.session = session
        session.dataTask(with: url).resume()
    }
    func cancel() { completion = nil; session?.invalidateAndCancel(); session = nil; received = Data() }
    private func finish(_ data: Data?) {
        let callback = completion; completion = nil; session?.invalidateAndCancel(); session = nil
        received = Data(); callback?(data)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              response.expectedContentLength <= Int64(ProxyImport.maximumBytes) else { completionHandler(.cancel); finish(nil); return }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard received.count + data.count <= ProxyImport.maximumBytes else { finish(nil); return }; received.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) { finish(error == nil ? received : nil) }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        guard let original = original, let next = request.url, next.scheme?.lowercased() == "https",
              next.host?.lowercased() == original.host?.lowercased(), (next.port ?? 443) == (original.port ?? 443),
              next.user == nil, next.password == nil else { completionHandler(nil); finish(nil); return }
        completionHandler(request)
    }
}

final class ProxyImportViewController: UIViewController, UIDocumentPickerDelegate {
    private let kind: VPN013ConnectionKind
    private let input = UITextView()
    private let submit = UIButton(type: .system)
    private let progress = UIActivityIndicatorView(style: .medium)
    private let downloader = ProxySubscriptionDownload()
    private var initialText: String?
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
        }
        #endif
    }
    @objc private func pasteText() {
        guard let value = UIPasteboard.general.string, value.utf8.count <= ProxyImport.maximumBytes else { show(ProxyProfileError.tooLarge); return }
        input.text = value
    }
    @objc private func pickFile() {
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
            guard data.count <= ProxyImport.maximumBytes, let text = String(data: data, encoding: .utf8) else { throw ProxyProfileError.tooLarge }
            input.text = text
        } catch { show(error is ProxyProfileError ? error : ProxyProfileError.invalid) }
    }
    @objc private func validateInput() {
        view.endEditing(true)
        let text = (input.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.utf8.count <= ProxyImport.maximumBytes else { show(ProxyProfileError.tooLarge); return }
        if let url = URL(string: text), url.scheme?.lowercased() == "https" {
            let alert = UIAlertController(title: "Загрузить подписку?", message: "VPN013 запросит конфигурации у \(url.host ?? "сервиса"). Ссылка не будет передана другим сайтам.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Загрузить", style: .default) { [weak self] _ in
                guard let self = self else { return }; self.busy(true)
                self.downloader.start(url) { [weak self] data in
                    guard let self = self else { return }; self.busy(false)
                    guard let data = data else { self.show(ProxyOperationError.system); return }; self.preview(data)
                }
            }); alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true)
        } else { preview(Data(text.utf8)) }
    }
    private func preview(_ data: Data) {
        do {
            let values = try ProxyImport.profiles(data, source: kind)
            let names = values.prefix(8).map { $0.name }.joined(separator: "\n")
            let alert = UIAlertController(title: "Серверов: \(values.count)", message: names + (values.count > 8 ? "\n…" : "") + "\n\nДобавить в раздел \(kind.title)?", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Добавить", style: .default) { [weak self] _ in
                guard let self = self else { return }; self.busy(true)
                ProxyProfilesManager.shared.add(values) { [weak self] error in
                    guard let self = self else { return }; self.busy(false)
                    if let error = error { self.show(error) } else { self.input.text = ""; self.navigationController?.popToRootViewController(animated: true) }
                }
            }); alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true)
        } catch { show(error is ProxyProfileError ? error : ProxyProfileError.invalid) }
    }
    private func busy(_ value: Bool) { submit.isEnabled = !value; input.isEditable = !value; value ? progress.startAnimating() : progress.stopAnimating() }
    private func show(_ error: Error) {
        let alert = UIAlertController(title: "Не удалось добавить", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}
