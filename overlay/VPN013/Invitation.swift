// SPDX-License-Identifier: MIT
import Foundation

enum VPN013Invitation {
    static let site = URL(string: "https://vpn013.com/")!
    static let cabinet = URL(string: "https://t.me/vpn013_com_bot?start=invite")!
    static let publicText = "Если Telegram не открывается, зайдите на https://vpn013.com/ — там можно скачать приложение и получить бесплатную конфигурацию на 1 час для первого подключения. Личный кабинет, покупка и продление: https://t.me/vpn013_com_bot"
    static let bonusText = "За первую покупку друга — 30% оплаченного срока на ваш бонусный баланс. Друг оплатил 30 дней — вам 9 бонусных дней. Вы сами выбираете, на какую свою подписку VPN013 их потратить: Happ, INCY, AmneziaWG или BlackTemple."
    static let attributionText = "Для бонуса отправляйте личную ссылку из кабинета VPN013. Общая ссылка на сайт не привязана к вашему аккаунту. Переход по ссылке и бесплатный тест бонусных дней не дают."
}

#if canImport(UIKit)
import UIKit

/// Public promotion never includes an imported profile, subscription URL,
/// device identity or bearer. Personal attribution belongs to the signed-in cabinet.
final class InvitationViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Пригласить друга"; view.backgroundColor = VPN013Theme.background
        let scroll = UIScrollView(); scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)
        let stack = UIStackView(); stack.axis = .vertical; stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false; scroll.addSubview(stack)
        func label(_ text: String, style: UIFont.TextStyle, secondary: Bool = false) -> UILabel {
            let value = UILabel(); value.text = text; value.numberOfLines = 0
            value.font = .preferredFont(forTextStyle: style); value.adjustsFontForContentSizeCategory = true
            value.textColor = secondary ? VPN013Theme.secondaryText : VPN013Theme.text
            return value
        }
        stack.addArrangedSubview(label("Бонусные дни", style: .title2))
        let bonus = label(VPN013Invitation.bonusText, style: .body)
        bonus.accessibilityIdentifier = "vpn013.invite.bonus"; stack.addArrangedSubview(bonus)
        stack.addArrangedSubview(label(VPN013Invitation.attributionText, style: .footnote, secondary: true))
        let personal = UIButton(type: .system)
        personal.setTitle("Моя ссылка и бонусный баланс", for: .normal)
        personal.addTarget(self, action: #selector(openCabinet), for: .touchUpInside)
        personal.accessibilityIdentifier = "vpn013.invite.personal"
        stack.addArrangedSubview(personal)
        stack.addArrangedSubview(label("Поделиться VPN013", style: .title2))
        let message = label(VPN013Invitation.publicText, style: .body, secondary: true)
        message.accessibilityIdentifier = "vpn013.invite.message"; stack.addArrangedSubview(message)
        let share = UIButton(type: .system)
        share.setTitle("Поделиться сайтом", for: .normal)
        share.setImage(UIImage(systemName: "square.and.arrow.up"), for: .normal)
        share.addTarget(self, action: #selector(shareSite(_:)), for: .touchUpInside)
        share.accessibilityIdentifier = "vpn013.invite.share"; stack.addArrangedSubview(share)
        for button in [personal, share] {
            button.tintColor = VPN013Theme.accent; button.titleLabel?.font = .preferredFont(forTextStyle: .headline)
            button.titleLabel?.adjustsFontForContentSizeCategory = true; button.titleLabel?.numberOfLines = 0
            button.heightAnchor.constraint(greaterThanOrEqualToConstant: 52).isActive = true
        }
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -24),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40)
        ])
    }
    @objc private func openCabinet() { UIApplication.shared.open(VPN013Invitation.cabinet) }
    @objc private func shareSite(_ sender: UIButton) {
        let share = UIActivityViewController(activityItems: [VPN013Invitation.publicText], applicationActivities: nil)
        share.popoverPresentationController?.sourceView = sender
        share.popoverPresentationController?.sourceRect = sender.bounds
        present(share, animated: true)
    }
}
#endif
