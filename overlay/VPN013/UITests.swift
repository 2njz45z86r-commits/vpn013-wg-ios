import XCTest
final class AutoTunnelUITests:XCTestCase {
    func testNativeRussianIPRouteObjectsPreserveVPNAndPeers() {
        let app=XCUIApplication()
        app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU","--vpn013-test-count","2","--vpn013-test-russian-routes"]
        app.launch()
        let policy=app.staticTexts["vpn013.routing-policy"]
        XCTAssertTrue(policy.waitForExistence(timeout:20))
        XCTAssertEqual(policy.value as? String,"8671 IPv4 / 2167 IPv6; original peers retained")
        capture("native-russian-ip-settings-objects-not-physical-traffic")
    }
    func capture(_ name:String) { let a=XCTAttachment(screenshot:XCUIScreen.main.screenshot());a.name=name;a.lifetime = .keepAlways;add(a) }
    private func assertProfileCount(_ app: XCUIApplication, _ count: Int, file: StaticString = #filePath, line: UInt = #line) {
        // UIKit exposes the same section-header UILabel through both its
        // legacy table element and modern accessibility container. Verify
        // every representation so an outdated header cannot be hidden.
        let labels = app.tables.staticTexts.matching(identifier: "vpn013.profile-count")
        XCTAssertGreaterThan(labels.count, 0, file: file, line: line)
        for label in labels.allElementsBoundByIndex {
            XCTAssertEqual(label.label, "Профили · \(count)", file: file, line: line)
        }
    }
    private func nativeTrialApp(_ variant: String = "") -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-native-trial" + variant]
        app.launch(); XCTAssertTrue(app.buttons["vpn013.add-profile"].waitForExistence(timeout:20)); return app
    }
    private func startNativeTrial(_ app: XCUIApplication) {
        app.buttons["vpn013.add-profile"].tap()
        XCTAssertTrue(app.buttons["Три дня теста бесплатно"].waitForExistence(timeout:5))
        XCTAssertFalse(app.buttons["1 час бесплатно"].exists)
        app.buttons["Три дня теста бесплатно"].tap()
    }
    private func trialImportResult(_ app: XCUIApplication) -> XCUIElement {
        let result = app.alerts["Тестовые профили добавлены"]
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline && !result.exists {
            let system = XCUIApplication(bundleIdentifier:"com.apple.springboard")
            for title in ["Allow", "Разрешить", "Don’t Allow", "Не разрешать"] {
                let button = system.alerts.buttons[title]
                if button.exists { button.tap(); break }
            }
            Thread.sleep(forTimeInterval:0.2)
        }
        XCTAssertTrue(result.exists); return result
    }
    func testNativeThreeDayTrialImportsFullZIPWithoutBrowser() {
        let app = nativeTrialApp(); startNativeTrial(app)
        let result = trialImportResult(app)
        XCTAssertTrue(result.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "Добавлено профилей: 2")).firstMatch.exists)
        XCTAssertTrue(result.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "выдач 1, загрузок 1")).firstMatch.exists)
        capture("native-three-day-import-synthetic-api-real-importer")
        result.buttons["Готово"].tap()
        for name in ["Личный сервер 1", "Личный сервер 2", "Тестовый сервер 1", "Тестовый сервер 2"] {
            XCTAssertTrue(app.tables.cells.staticTexts[name].exists)
        }
        XCTAssertTrue(app.navigationBars["VPN013"].exists)
        assertProfileCount(app, 4)
        capture("native-three-day-import-profile-count-four")
    }
    func testNativeThreeDayRepeatedButtonKeepsSameProfiles() {
        let app = nativeTrialApp(); startNativeTrial(app); trialImportResult(app).buttons["Готово"].tap()
        startNativeTrial(app); let result = trialImportResult(app)
        XCTAssertTrue(result.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "выдач 1, загрузок 2")).firstMatch.exists)
        result.buttons["Готово"].tap()
        XCTAssertEqual(app.tables.cells.staticTexts.matching(identifier:"Тестовый сервер 1").count,1)
        XCTAssertEqual(app.tables.cells.staticTexts.matching(identifier:"Тестовый сервер 2").count,1)
        assertProfileCount(app, 4)
        capture("native-three-day-repeat-no-new-grant-or-profiles")
    }
    func testNativeThreeDayUnsafeZIPPreservesExistingProfiles() {
        let app = nativeTrialApp("-bad-zip"); startNativeTrial(app)
        let alert = app.alerts["Тест не добавлен"]
        XCTAssertTrue(alert.waitForExistence(timeout:15)); capture("native-three-day-unsafe-zip-refused")
        alert.buttons["Готово"].tap()
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 1"].exists)
        XCTAssertFalse(app.tables.cells.staticTexts["Тестовый сервер 1"].exists)
    }
    func testNativeThreeDayExpiredOffersPersonalRenewalWithoutImport() {
        let app = nativeTrialApp("-expired"); startNativeTrial(app)
        let alert = app.alerts["Срок доступа закончился"]
        XCTAssertTrue(alert.waitForExistence(timeout:10))
        XCTAssertTrue(alert.buttons["Продлить конфигурацию"].isEnabled)
        capture("native-three-day-expired-personal-renewal")
        alert.buttons["Позже"].tap()
        XCTAssertFalse(app.tables.cells.staticTexts["Тестовый сервер 1"].exists)
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 1"].exists)
    }
    func testCreateAutomaticFromThirteenImportedFixtures() {
        let app=XCUIApplication();app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU"];app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["Беларусь"].waitForExistence(timeout:20))
        capture("01-thirteen-servers-simulator-fixture")
        app.buttons["vpn013.add-profile"].tap()
        XCTAssertTrue(app.buttons["Создать режим Авто"].waitForExistence(timeout:4))
        app.buttons["Создать режим Авто"].tap()
        XCTAssertTrue(app.alerts["Создать режим Авто"].waitForExistence(timeout:4))
        capture("02-auto-confirmation-simulator-fixture")
        app.alerts.buttons["Создать Авто"].tap()
        XCTAssertTrue(app.staticTexts["Авто · 13 серверов"].waitForExistence(timeout:6))
        capture("03-auto-profile-simulator-fixture")
    }

    func testSharedZipImportsThirteenWithoutDuplicateError() {
        let app=XCUIApplication()
        app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU","--vpn013-test-import"]
        app.launch()
        XCTAssertTrue(app.staticTexts["Швеция"].waitForExistence(timeout:20))
        XCTAssertEqual(app.alerts.count,0)
        assertProfileCount(app, 13)
        for name in ["Беларусь","Германия","Германия 2","Грузия","Испания","Нидерланды","Польша","Польша 2","США","Турция","Финляндия","Финляндия 2","Швеция"] {
            XCTAssertEqual(app.tables.cells.staticTexts.matching(identifier:name).count,1)
        }
        capture("04-shared-zip-26-files-13-imported")
        app.buttons["vpn013.add-profile"].tap()
        app.buttons["Создать режим Авто"].tap()
        XCTAssertTrue(app.alerts["Создать режим Авто"].waitForExistence(timeout:5))
        app.alerts.buttons["Создать Авто"].tap()
        XCTAssertTrue(app.staticTexts["Авто · 13 серверов"].waitForExistence(timeout:6))
    }

    private func createFromPersonalServers(count: Int, label: String) {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", String(count)]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 1"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        let action = app.buttons["Создать режим Авто"]
        XCTAssertTrue(action.waitForExistence(timeout:5)); XCTAssertTrue(action.isEnabled)
        action.tap()
        let confirmation = app.alerts["Создать режим Авто"]
        XCTAssertTrue(confirmation.waitForExistence(timeout:5))
        XCTAssertTrue(confirmation.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "В режиме Авто: " + label)).firstMatch.exists)
        capture("dynamic-\(count)-personal-servers-confirmation")
        confirmation.buttons["Создать Авто"].tap()
        XCTAssertTrue(app.navigationBars["Авто · " + label].waitForExistence(timeout:6))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "В режиме Авто: " + label)).firstMatch.exists)
        capture("dynamic-\(count)-personal-servers-saved")
    }

    func testFivePersonalServers() { createFromPersonalServers(count:5, label:"5 серверов") }
    func testTwoPersonalServers() { createFromPersonalServers(count:2, label:"2 сервера") }
    func testSinglePersonalServerExplainsNoReserve() { createFromPersonalServers(count:1, label:"1 сервер") }
    func testMoreThanThirteenPersonalServers() { createFromPersonalServers(count:26, label:"26 серверов") }
    func testThirtyPersonalServers() { createFromPersonalServers(count:30, label:"30 серверов") }
    func testFourteenPersonalServers() { createFromPersonalServers(count:14, label:"14 серверов") }
    func testEmptyListDisablesAutomaticCreation() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "0"]
        app.launch()
        XCTAssertTrue(app.buttons["vpn013.add-profile"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        XCTAssertTrue(app.buttons["Купить конфигурацию"].isEnabled)
        XCTAssertTrue(app.buttons["Три дня теста бесплатно"].isEnabled)
        let action = app.buttons["Создать режим Авто"]
        XCTAssertTrue(action.waitForExistence(timeout:5)); XCTAssertFalse(action.isEnabled)
        capture("dynamic-0-creation-disabled")
    }

    func testUpdateDownloadUsesDirectIPAInsteadOfTelegram() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-direct-download"]
        app.launch()
        XCTAssertTrue(app.buttons["vpn013.updates"].waitForExistence(timeout:20))
        app.buttons["vpn013.updates"].tap()
        let download = app.tables.cells.containing(.staticText, identifier: "Скачать IPA").firstMatch
        XCTAssertTrue(download.waitForExistence(timeout:5))
        XCTAssertFalse(app.staticTexts["Скачать обновление в боте"].exists)
        XCTAssertFalse(app.buttons["Перейти в бот"].exists)
        download.tap()
        let alert = app.alerts["Прямая загрузка IPA"]
        XCTAssertTrue(alert.waitForExistence(timeout:5))
        XCTAssertTrue(alert.staticTexts["https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/unsigned-test/VPN013AWG-unsigned.ipa"].exists)
        capture("direct-ipa-download-no-telegram-synthetic-ui-fixture")
        alert.buttons["Понятно"].tap()
    }

    func testSettingsBrandWordmarkAndVersionUseShortName() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2"]
        app.launch()
        XCTAssertTrue(app.navigationBars["VPN013"].waitForExistence(timeout:20))
        app.buttons["Настройки"].tap()
        XCTAssertTrue(app.staticTexts["VPN013"].waitForExistence(timeout:5))
        let wordmark = app.images["vpn013.settings-wordmark"]
        for _ in 0..<3 {
            if wordmark.isHittable { break }
            app.tables.firstMatch.swipeUp()
        }
        XCTAssertTrue(wordmark.exists && wordmark.isHittable)
        XCTAssertEqual(wordmark.label, "VPN013")
        XCTAssertFalse(app.staticTexts["VPN013.com WG"].exists)
        capture("settings-short-name-and-rendered-wordmark-no-domain")
    }

    func testCenteredAddShowsPurchaseAndThreeDayTrial() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "0"]
        app.launch()
        let add = app.buttons.matching(identifier: "addEmptyStateButton").firstMatch
        XCTAssertTrue(add.waitForExistence(timeout:20))
        add.tap()
        XCTAssertTrue(app.buttons["Купить конфигурацию"].waitForExistence(timeout:5))
        XCTAssertTrue(app.buttons["Купить конфигурацию"].isEnabled)
        XCTAssertTrue(app.buttons["Три дня теста бесплатно"].isEnabled)
        capture("empty-list-centered-add-purchase-menu")
    }

    func testRedesignedListKeepsNativeControls() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2"]
        app.launch()
        XCTAssertTrue(app.navigationBars["VPN013"].waitForExistence(timeout:20))
        let profile = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:5))
        let toggle = profile.switches.firstMatch
        XCTAssertTrue(toggle.exists)
        XCTAssertTrue(toggle.isEnabled)
        XCTAssertTrue(toggle.isHittable)
        XCTAssertLessThanOrEqual(toggle.frame.width, 80, "The native switch must not stretch across the row")
        let latency = profile.staticTexts["vpn013.latency"]
        XCTAssertTrue(latency.exists)
        XCTAssertLessThan(latency.frame.maxX, toggle.frame.minX)
        XCTAssertTrue(app.buttons["Настройки"].isHittable)
        XCTAssertTrue(app.buttons["vpn013.add-profile"].isHittable)
        capture("07-dark-native-list-two-personal-servers")
        profile.staticTexts["Личный сервер 1"].tap()
        XCTAssertTrue(app.navigationBars["Личный сервер 1"].waitForExistence(timeout:5))
        capture("08-dark-list-opens-profile-detail")
    }

    func testAddMenuKeepsAllActions() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2"]
        app.launch()
        let add = app.buttons["vpn013.add-profile"]
        XCTAssertTrue(add.waitForExistence(timeout:20))
        add.tap()
        XCTAssertTrue(app.buttons["Купить конфигурацию"].waitForExistence(timeout:5))
        for title in ["Купить конфигурацию", "Три дня теста бесплатно", "Продлить конфигурацию", "Создать из файла или архива", "Создать режим Авто", "Создать из QR-кода", "Создать с нуля"] {
            let action = app.buttons[title]
            XCTAssertTrue(action.exists, "Missing add-menu action: " + title)
            XCTAssertTrue(action.isEnabled, "Disabled add-menu action: " + title)
        }
        capture("09-dark-list-complete-add-menu")
        app.buttons["Создать с нуля"].tap()
        XCTAssertTrue(app.navigationBars["Новая конфигурация"].waitForExistence(timeout:5))
        capture("09b-native-new-config-form")
        app.navigationBars["Новая конфигурация"].buttons["Отменить"].tap()
        XCTAssertTrue(app.navigationBars["VPN013"].waitForExistence(timeout:5))
    }

    func testDeveloperFooterAvailable() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "-AppleInterfaceStyle", "Dark"]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["Беларусь"].waitForExistence(timeout:20))
        capture("10-dark-thirteen-profile-list-top-simulator-fixture")
        let support = app.buttons["vpn013.developer-support"]
        for _ in 0..<8 {
            if support.exists && support.isHittable { break }
            app.tables.firstMatch.swipeUp()
        }
        XCTAssertTrue(support.exists)
        XCTAssertTrue(support.isHittable)
        XCTAssertTrue(support.isEnabled)
        XCTAssertTrue(support.label.contains("@R013_Support"))
        XCTAssertTrue(app.staticTexts["Разработчик VPN013"].exists)
        capture("11-dark-thirteen-profile-list-developer-footer-simulator-fixture")
    }

    func testDarkEmptyListKeepsDeveloperFooter() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "-AppleInterfaceStyle", "Dark", "--vpn013-test-count", "0"]
        app.launch()
        let add = app.buttons["addEmptyStateButton"]
        XCTAssertTrue(add.waitForExistence(timeout:20))
        XCTAssertTrue(add.isHittable)
        let support = app.buttons["vpn013.developer-support"]
        for _ in 0..<4 {
            if support.exists && support.isHittable { break }
            app.tables.firstMatch.swipeUp()
        }
        XCTAssertTrue(support.exists)
        XCTAssertTrue(support.isHittable)
        XCTAssertTrue(support.label.contains("@R013_Support"))
        XCTAssertTrue(app.staticTexts["Разработчик VPN013"].exists)
        XCTAssertTrue(add.isHittable)
        capture("12-dark-empty-list-developer-footer-simulator-fixture")
    }

    func testLargeTextKeepsSwitchAndDeveloperFooter() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU",
                               "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
                               "--vpn013-test-count", "2"]
        app.launch()
        let first = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(first.waitForExistence(timeout:20))
        // The accessible summary may occupy the first viewport; the list scrolls.
        for _ in 0..<8 {
            if first.switches.firstMatch.isHittable { break }
            app.tables.firstMatch.swipeUp()
        }
        XCTAssertTrue(first.switches.firstMatch.isHittable)
        capture("13-large-type-list-simulator-fixture")
        let support = app.buttons["vpn013.developer-support"]
        for _ in 0..<8 {
            if support.exists && support.isHittable { break }
            app.tables.firstMatch.swipeUp()
        }
        XCTAssertTrue(support.isHittable)
        capture("14-large-type-developer-footer-simulator-fixture")
    }

    func testUnavailableLogStopsSpinnerAndShowsExplanation() {
        let app=XCUIApplication()
        app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU","--vpn013-test-no-log"]
        app.launch()
        XCTAssertTrue(app.buttons["Настройки"].waitForExistence(timeout:20))
        app.buttons["Настройки"].tap()
        app.buttons["vpn013.view-log"].tap()
        let logText = app.textViews.matching(identifier:"vpn013.log-content").firstMatch
        XCTAssertTrue(logText.waitForExistence(timeout:5))
        XCTAssertTrue((logText.value as? String ?? "").contains("Журнал недоступен"))
        XCTAssertFalse(app.activityIndicators["vpn013.log-loading"].isHittable)
        capture("06-log-unavailable-no-infinite-spinner-simulated")
    }

    func testPingButtonMeasuresActualLoopbackWithoutStartingVPN() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-ping-loopback"]
        app.launch()
        let button = app.buttons["vpn013.check-ping"]
        XCTAssertTrue(button.waitForExistence(timeout:20))
        XCTAssertTrue(button.isHittable)
        button.tap()
        let first = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        let measured = first.staticTexts.matching(NSPredicate(format:"label ENDSWITH %@", "мс")).firstMatch
        XCTAssertTrue(measured.waitForExistence(timeout:10), "Actual localhost echo must populate the delay column")
        XCTAssertEqual(first.switches.firstMatch.value as? String, "0", "Ping must not activate the VPN")
        XCTAssertTrue(app.staticTexts["vpn013.ping-explanation"].label.contains("Это пинг"))
        XCTAssertEqual(button.label, "Проверить пинг")
        capture("15-real-loopback-ping-results-no-vpn-switch")
    }

    func testPingCancellationIsAvailable() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2"]
        app.launch()
        let button = app.buttons["vpn013.check-ping"]
        XCTAssertTrue(button.waitForExistence(timeout:20))
        button.tap()
        XCTAssertTrue(app.buttons["Остановить проверку"].waitForExistence(timeout:2))
        button.tap()
        XCTAssertEqual(button.label, "Проверить пинг")
        XCTAssertTrue(app.staticTexts["vpn013.ping-explanation"].label.contains("остановлена"))
        capture("16-ping-cancelled")
    }

    func testAutoPinnedFirstWithCurrentMemberAndPing() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-ordering", "--vpn013-test-current-card", "--vpn013-test-ping-loopback"]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["!Первый"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        app.buttons["Создать режим Авто"].tap()
        XCTAssertTrue(app.alerts["Создать режим Авто"].waitForExistence(timeout:5))
        app.alerts.buttons["Создать Авто"].tap()
        capture("20a-after-auto-creation-synthetic")
        let firstAuto = app.tables.cells.element(boundBy:0).staticTexts["Авто · 3 сервера"]
        if !firstAuto.waitForExistence(timeout:2) {
            let explanation = app.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "В режиме Авто: 3 сервера")).firstMatch
            guard explanation.waitForExistence(timeout:6) else {
                capture("20b-auto-creation-unexpected-screen-synthetic")
                XCTFail("Auto creation did not reach either its detail or its list row"); return
            }
            app.navigationBars.buttons.element(boundBy:0).tap()
        }
        XCTAssertTrue(app.tables.cells.element(boundBy:0).staticTexts["Авто · 3 сервера"].waitForExistence(timeout:6), "Auto must precede ! and 0 names")
        let auto = app.tables.cells.element(boundBy:0)
        auto.switches.firstMatch.tap()
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout:8))
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].waitForExistence(timeout:8))
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Дом", "Card must show actual Auto member, not its seed")
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].label.contains("127.0.0.1:4444"))
        XCTAssertTrue(app.staticTexts["vpn013.current-traffic"].exists)
        XCTAssertTrue(ping.isEnabled && ping.isHittable)
        XCTAssertGreaterThanOrEqual(ping.frame.height, 44)
        ping.tap()
        let result = app.staticTexts.matching(NSPredicate(format:"identifier == %@ AND label ENDSWITH %@", "vpn013.current-ping-result", "мс")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout:10), "Current-server button must show a real loopback echo result")
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "1", "Current-server Ping cannot switch off Auto")
        capture("20-auto-first-current-member-real-loopback-ping-synthetic-vpn")
        auto.switches.firstMatch.tap()
        XCTAssertFalse(ping.isHittable, "No current-server action after VPN is off")
    }

    func testManualCurrentServerPingAndInfo() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-current-card", "--vpn013-test-ping-loopback"]
        app.launch()
        let profile = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:20))
        profile.switches.firstMatch.tap()
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].waitForExistence(timeout:8))
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 1")
        XCTAssertTrue(ping.isHittable && ping.isEnabled)
        ping.tap()
        let result = app.staticTexts.matching(NSPredicate(format:"identifier == %@ AND label ENDSWITH %@", "vpn013.current-ping-result", "мс")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout:10))
        XCTAssertEqual(profile.switches.firstMatch.value as? String, "1")
        capture("21-current-manual-server-real-loopback-ping-synthetic-vpn")
        XCUIDevice.shared.orientation = .landscapeLeft
        capture("22-current-manual-server-landscape-synthetic-vpn")
        XCUIDevice.shared.orientation = .portrait
        let portraitReady = XCTNSPredicateExpectation(predicate: NSPredicate(format: "hittable == true AND value == '1'"), object: profile.switches.firstMatch)
        XCTAssertEqual(XCTWaiter.wait(for: [portraitReady], timeout: 5), .completed)
        profile.switches.firstMatch.tap()
        let disconnected = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '0'"), object: profile.switches.firstMatch)
        XCTAssertEqual(XCTWaiter.wait(for: [disconnected], timeout: 5), .completed)
        let pingHidden = XCTNSPredicateExpectation(predicate: NSPredicate(format: "hittable == false"), object: ping)
        XCTAssertEqual(XCTWaiter.wait(for: [pingHidden], timeout: 5), .completed)
    }

    func testManualHandshakeSummaryUsesReturnedRuntimeData() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-current-card", "--vpn013-test-current-handshake"]
        app.launch()
        let profile = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:20))
        profile.switches.firstMatch.tap()
        let proof = app.staticTexts["vpn013.current-proof"]
        let received = XCTNSPredicateExpectation(predicate: NSPredicate(format:"label == %@", "Данные рукопожатия получены"), object: proof)
        XCTAssertEqual(XCTWaiter.wait(for:[received], timeout:8), .completed)
        XCTAssertTrue(app.staticTexts["vpn013.current-handshake"].label.hasPrefix("Рукопожатие:"))
        XCTAssertFalse(app.staticTexts["vpn013.current-traffic"].label.contains("недоступна"))
        XCTAssertEqual(profile.switches.firstMatch.value as? String, "1")
        capture("manual-runtime-handshake-summary-synthetic-no-internet-proof")
    }

    private func checkManualPingWithoutRuntime(_ fixture: String, captureName: String) {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", fixture, "--vpn013-test-ping-loopback"]
        app.launch()
        let profile = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:20))
        profile.switches.firstMatch.tap()
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout:8))
        XCTAssertTrue(ping.isEnabled && ping.isHittable, "Saved ordinary address must remain usable without extension statistics")
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].label.contains("127.0.0.1"))
        XCTAssertEqual(app.staticTexts["vpn013.current-traffic"].label, "Статистика VPN пока недоступна")
        let explanation = app.staticTexts["vpn013.current-handshake"]
        let expectedExplanation = fixture == "--vpn013-test-current-card-timeout"
            ? "Нет ответа VPN-расширения за 6 секунд" : "VPN-расширение не вернуло данные статистики"
        let matchingExplanation = app.staticTexts.matching(NSPredicate(format:"identifier == %@ AND label == %@", "vpn013.current-handshake", expectedExplanation)).firstMatch
        XCTAssertTrue(matchingExplanation.waitForExistence(timeout:10))
        XCTAssertEqual(explanation.label, expectedExplanation)
        XCTAssertEqual(app.staticTexts["vpn013.current-proof"].label, "Данные рукопожатия пока недоступны")
        ping.tap()
        let result = app.staticTexts.matching(NSPredicate(format:"identifier == %@ AND label ENDSWITH %@", "vpn013.current-ping-result", "мс")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout:10), "Button must perform a real loopback ICMP echo")
        let measured = result.label
        // Keep the measured Ping across two bounded six-second request windows.
        let refreshes = expectation(description:"Two runtime refresh cycles")
        DispatchQueue.main.asyncAfter(deadline:.now() + 14) { refreshes.fulfill() }
        wait(for:[refreshes], timeout:16)
        XCTAssertTrue(ping.isEnabled)
        XCTAssertEqual(app.staticTexts["vpn013.current-ping-result"].label, measured, "Missing runtime must not erase the measured Ping")
        XCTAssertEqual(profile.switches.firstMatch.value as? String, "1", "Ping and refresh must not replace the running VPN")
        capture(captureName)
        profile.switches.firstMatch.tap()
        XCTAssertFalse(ping.isHittable, "Unavailable or late runtime cannot resurrect the disconnected card")
    }

    func testManualCurrentPingWithMissingRuntime() {
        checkManualPingWithoutRuntime("--vpn013-test-current-card-missing", captureName:"23-manual-ping-without-runtime-real-loopback-synthetic-vpn")
    }

    func testManualCurrentPingWithRuntimeTimeout() {
        checkManualPingWithoutRuntime("--vpn013-test-current-card-timeout", captureName:"24-manual-ping-runtime-timeout-real-loopback-synthetic-vpn")
    }

    func testAutoMissingRuntimeDoesNotPingSeed() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-current-card-missing", "--vpn013-test-ping-loopback"]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 1"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        app.buttons["Создать режим Авто"].tap()
        XCTAssertTrue(app.alerts["Создать режим Авто"].waitForExistence(timeout:5))
        app.alerts.buttons["Создать Авто"].tap()
        // Creation always opens the detail controller. A hidden list element
        // can still exist in UIKit's accessibility tree; existence is not a
        // reason to skip the visible Back action.
        let detail = app.navigationBars["Авто · 2 сервера"]
        XCTAssertTrue(detail.waitForExistence(timeout:8))
        capture("25a-auto-created-detail-before-explicit-back")
        let back = detail.buttons["VPN013"]
        let backReady = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in back.exists && back.isHittable }, object:back)
        XCTAssertEqual(XCTWaiter.wait(for:[backReady], timeout:8), .completed)
        back.tap()
        let add = app.buttons["vpn013.add-profile"]
        let listReady = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in add.exists && add.isHittable }, object:add)
        XCTAssertEqual(XCTWaiter.wait(for:[listReady], timeout:8), .completed)
        capture("25b-visible-profile-list-after-explicit-back")
        let auto = app.tables.cells.element(boundBy:0)
        XCTAssertTrue(auto.staticTexts["Авто · 2 сервера"].waitForExistence(timeout:6))
        auto.switches.firstMatch.tap()
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout:8))
        XCTAssertFalse(ping.isEnabled, "Unknown Auto member cannot be replaced by its saved seed")
        XCTAssertEqual(app.staticTexts["vpn013.current-endpoint"].label, "Текущий сервер пока недоступен")
        capture("25-auto-unknown-member-no-seed-ping-synthetic-vpn")
        auto.switches.firstMatch.tap()
    }

    private func waitForPowerValue(_ value: String, in app: XCUIApplication) -> XCUIElement {
        let button = app.buttons["vpn013.current-power"]
        XCTAssertTrue(button.waitForExistence(timeout: 10))
        let state = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", value), object: button)
        XCTAssertEqual(XCTWaiter.wait(for: [state], timeout: 8), .completed)
        return button
    }

    func testCurrentPowerButtonRemembersManualProfile() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-current-card-missing"]
        app.launch()
        let first = app.tables.cells.containing(.staticText, identifier: "Личный сервер 1").firstMatch
        let second = app.tables.cells.containing(.staticText, identifier: "Личный сервер 2").firstMatch
        XCTAssertTrue(first.waitForExistence(timeout: 20))
        let power = waitForPowerValue("Выключен", in: app)
        XCTAssertTrue(power.isEnabled && power.isHittable)
        XCTAssertGreaterThanOrEqual(power.frame.width, 44)
        XCTAssertEqual(power.frame.width, power.frame.height, accuracy: 0.5)
        capture("26a-current-power-off-synthetic")
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(first.switches.firstMatch.value as? String, "1")
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 1")
        capture("26b-current-power-on-without-runtime-synthetic")
        power.tap()
        _ = waitForPowerValue("Выключен", in: app)
        XCTAssertEqual(first.switches.firstMatch.value as? String, "0")
        second.switches.firstMatch.tap()
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 2")
        power.tap()
        _ = waitForPowerValue("Выключен", in: app)
        XCTAssertEqual(second.switches.firstMatch.value as? String, "0")
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 2")
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(second.switches.firstMatch.value as? String, "1", "Reconnect the last actual profile, not the first row")
        XCTAssertEqual(first.switches.firstMatch.value as? String, "0")
        capture("26c-current-power-remembers-second-manual-profile-synthetic")
    }

    func testCurrentPowerButtonControlsAutoWithoutRuntime() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-current-card-missing"]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 1"].waitForExistence(timeout: 20))
        app.buttons["vpn013.add-profile"].tap()
        app.buttons["Создать режим Авто"].tap()
        XCTAssertTrue(app.alerts["Создать режим Авто"].waitForExistence(timeout: 5))
        app.alerts.buttons["Создать Авто"].tap()
        if !app.tables.cells.element(boundBy: 0).staticTexts["Авто · 2 сервера"].waitForExistence(timeout: 2) {
            XCTAssertTrue(app.navigationBars["Авто · 2 сервера"].waitForExistence(timeout: 6))
            app.navigationBars.buttons.element(boundBy: 0).tap()
        }
        let auto = app.tables.cells.element(boundBy: 0)
        XCTAssertTrue(auto.staticTexts["Авто · 2 сервера"].waitForExistence(timeout: 6))
        let power = waitForPowerValue("Выключен", in: app)
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Авто · 2 сервера")
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "1")
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout: 8))
        XCTAssertFalse(ping.isEnabled, "Unknown Auto member must still not ping a saved seed")
        XCTAssertTrue(power.isEnabled && power.isHittable, "Power depends on the connection, not runtime statistics")
        capture("27-current-power-auto-without-member-statistics-synthetic")
        power.tap()
        _ = waitForPowerValue("Выключен", in: app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "0")
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "1")
    }

    func testCurrentPowerButtonEmptyAndLargeType() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "0"]
        app.launch()
        let emptyPower = waitForPowerValue("Выключен", in: app)
        XCTAssertFalse(emptyPower.isEnabled, "No profile may be invented or connected from an empty list")
        capture("28a-current-power-empty-disabled-synthetic")
        app.terminate()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU",
            "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
            "--vpn013-test-count", "2", "--vpn013-test-current-card", "--vpn013-test-start-current"]
        app.launch()
        let power = waitForPowerValue("Включён", in: app)
        for _ in 0..<5 {
            if power.isHittable { break }
            app.tables.firstMatch.swipeUp()
        }
        XCTAssertTrue(power.isHittable)
        XCTAssertGreaterThanOrEqual(power.frame.height, 44)
        XCTAssertGreaterThanOrEqual(power.frame.minX, 0)
        XCTAssertLessThanOrEqual(power.frame.maxX, app.windows.firstMatch.frame.maxX)
        let ping = app.buttons["vpn013.current-ping"]
        if ping.exists { XCTAssertFalse(power.frame.intersects(ping.frame), "Power and Ping must remain separate targets") }
        capture("28b-current-power-large-type-synthetic")
    }

    func testCurrentPowerButtonDisabledDuringTransition() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU",
            "--vpn013-test-count", "2", "--vpn013-test-power-connecting"]
        app.launch()
        let power = waitForPowerValue("Изменение подключения", in: app)
        XCTAssertFalse(power.isEnabled, "A second activation must not be submitted during a transition")
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == %@", "Подключение…")).firstMatch.exists)
        capture("29-current-power-connecting-disabled-synthetic")
    }

    func testUpdatesScreenAndOrderSynchronization() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-sync"]
        app.launch()
        let updates = app.buttons["vpn013.updates"]
        XCTAssertTrue(updates.waitForExistence(timeout:20))
        updates.tap()
        XCTAssertTrue(app.staticTexts["Пока нет привязанных заявок"].waitForExistence(timeout:5))
        XCTAssertTrue(app.cells["vpn013.update-check"].exists)
        capture("17-updates-before-binding")
        let fixture = app.cells["vpn013.sync-fixture"]
        for _ in 0..<5 { if fixture.isHittable { break }; app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(fixture.isHittable)
        fixture.tap()
        let passed = app.staticTexts["Проверено: добавление, удаление, ключи, сторонний профиль и Авто · 3 сервера"]
        XCTAssertTrue(passed.waitForExistence(timeout:15))
        capture("18-order-sync-invariants-passed-synthetic")
        app.navigationBars["Обновления"].buttons["Готово"].tap()
        XCTAssertTrue(app.tables.cells.staticTexts["Managed B"].waitForExistence(timeout:5))
        XCTAssertFalse(app.tables.cells.staticTexts["Личный сервер 1"].exists)
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 2"].exists)
        capture("19-updated-order-and-foreign-profile-preserved-synthetic")
    }
}
