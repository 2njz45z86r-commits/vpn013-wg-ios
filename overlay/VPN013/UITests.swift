import XCTest
final class AutoTunnelUITests:XCTestCase {
    override func tearDown() {
        if let run = testRun, run.failureCount > 0 { capture("failed-" + name) }
        super.tearDown()
    }
    func testServiceCatalogGroupsExclusiveModesAndRememberedSelection() {
        // Stop after an actual assertion failure instead of repeating a failed
        // text event across the three sections for several minutes.
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch()
        func openCatalog() {
            if !app.buttons["vpn013.settings.routing"].exists { app.buttons["vpn013.settings"].tap() }
            app.buttons["vpn013.settings.routing"].tap()
            app.buttons["vpn013.routing.select-all"].tap(); app.buttons["vpn013.routing.next"].tap()
            app.buttons["vpn013.services.open"].tap()
            XCTAssertTrue(app.switches["vpn013.services.only"].waitForExistence(timeout: 8))
        }
        func searchForFacebook() {
            let search = app.searchFields.firstMatch
            XCTAssertTrue(search.waitForExistence(timeout: 10), "The service search must exist")
            let keyboard = app.keyboards.firstMatch
            for _ in 0..<3 {
                if !search.isHittable { app.tables.firstMatch.swipeDown() }
                if search.isHittable {
                    search.tap()
                    if keyboard.waitForExistence(timeout: 5) { break }
                }
            }
            XCTAssertTrue(search.isHittable, "The service search must be reachable")
            XCTAssertTrue(keyboard.exists, "Tapping the service search must open the keyboard")
            search.typeText("Facebook\n")
        }
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            app.buttons["vpn013.proxy.add"].tap(); app.buttons["vpn013.proxy.import.check"].tap()
            XCTAssertTrue(app.alerts["Серверов: 1"].waitForExistence(timeout: 5)); app.alerts.buttons["Добавить"].tap()
            openCatalog()
            let only = app.switches["vpn013.services.only"], bypass = app.switches["vpn013.services.bypass"]
            XCTAssertEqual(only.value as? String, "0"); XCTAssertEqual(bypass.value as? String, "0")
            XCTAssertGreaterThan(app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH %@", "vpn013.services.group.")).count, 0)
            capture("catalog-" + kind + "-groups-default-off")
            only.tap(); XCTAssertEqual(only.value as? String, "1"); XCTAssertEqual(bypass.value as? String, "0")
            searchForFacebook()
            let service = app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@ AND label CONTAINS %@", "vpn013.services.item.", "Facebook")).firstMatch
            XCTAssertTrue(service.waitForExistence(timeout: 5)); XCTAssertTrue(service.label.contains("Facebook"))
            XCTAssertTrue(service.isHittable, "Search results must remain reachable after dismissing the keyboard")
            service.tap(); XCTAssertEqual(service.value as? String, "Выбрано")
            bypass.tap(); XCTAssertEqual(only.value as? String, "0"); XCTAssertEqual(bypass.value as? String, "1")
            XCTAssertEqual(service.value as? String, "Не выбрано"); service.tap()
            func captureSwitchDiagnostic(_ stage: String) {
                let screenshot = XCTAttachment(screenshot: app.screenshot())
                screenshot.name = "switch-" + kind + "-" + stage
                screenshot.lifetime = .keepAlways
                add(screenshot)
                let hierarchy = XCTAttachment(string: app.debugDescription)
                hierarchy.name = "hierarchy-" + kind + "-" + stage
                hierarchy.lifetime = .keepAlways
                add(hierarchy)
            }
            captureSwitchDiagnostic("before-disable")
            bypass.tap()
            captureSwitchDiagnostic("after-disable")
            XCTAssertEqual(only.value as? String, "0", "Only mode must stay off after disabling bypass")
            XCTAssertEqual(bypass.value as? String, "0", "Bypass mode must switch off on the second tap")
            app.buttons["vpn013.services.save"].tap()
            openCatalog(); only.tap()
            searchForFacebook()
            let saved = app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@ AND label CONTAINS %@", "vpn013.services.item.", "Facebook")).firstMatch
            XCTAssertTrue(saved.waitForExistence(timeout: 5))
            // Search filtering and UITableView reload can briefly expose a stale cell.
            // Wait for the actual searched service and its saved selection; never
            // tap it or relax the final state assertion to make the test pass.
            let remembered = NSPredicate(format: "label CONTAINS %@ AND value == %@", "Facebook", "Выбрано")
            let selectedResult = XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: remembered, object: saved)], timeout: 10)
            XCTAssertEqual(selectedResult, .completed)
            XCTAssertTrue(saved.label.contains("Facebook"))
            XCTAssertEqual(saved.value as? String, "Выбрано")
            capture("catalog-" + kind + "-remembered-choice-no-vpn-started")
            only.tap(); app.buttons["vpn013.services.save"].tap()
            let close = app.buttons["vpn013.settings.done"]
            if close.exists { close.tap() }
        }
    }
    func testWireGuardServicesUseOwnServersAndKeepUnselectedConfiguration() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "3", "--vpn013-test-unified", "--vpn013-test-wg-service-routing"]
        app.launch()
        app.tabBars.buttons["vpn013.kind.amneziawg"].tap()
        openConnectionPopup(app, title: "AmneziaWG")
        let proof = app.staticTexts["vpn013.routing-policy"]
        XCTAssertTrue(proof.waitForExistence(timeout: 20))
        XCTAssertTrue((proof.value as? String)?.contains("WG bulk: ownership, active/on-demand guards, 2/3 scope, original configs, retained OFF choices passed") == true)
        closeConnectionPopup(app)
        func openServers() {
            if !app.buttons["vpn013.settings.routing"].exists { app.buttons["vpn013.settings"].tap() }
            app.buttons["vpn013.settings.routing"].tap()
            XCTAssertTrue(app.buttons["vpn013.routing.next"].waitForExistence(timeout: 5))
        }
        openServers()
        let cells = app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@", "vpn013.routing.wg-server."))
        XCTAssertEqual(cells.count, 3)
        app.buttons["vpn013.routing.select-all"].tap(); XCTAssertEqual(app.buttons["vpn013.routing.next"].label, "Далее (3)")
        app.buttons["vpn013.routing.select-all"].tap(); XCTAssertFalse(app.buttons["vpn013.routing.next"].isEnabled)
        cells.element(boundBy: 0).tap(); cells.element(boundBy: 1).tap(); app.buttons["vpn013.routing.next"].tap()
        let only = app.switches["vpn013.services.only"], bypass = app.switches["vpn013.services.bypass"]
        XCTAssertTrue(only.waitForExistence(timeout: 5)); XCTAssertEqual(only.value as? String, "0"); XCTAssertEqual(bypass.value as? String, "0")
        only.tap(); let search = app.searchFields.firstMatch; search.tap(); search.typeText("Facebook")
        let service = app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@", "vpn013.services.item.")).firstMatch
        XCTAssertTrue(service.waitForExistence(timeout: 5)); XCTAssertEqual(service.label, "Facebook"); service.tap()
        capture("wg-services-two-of-three-explicit-only")
        app.buttons["vpn013.services.save"].tap()
        for index in 0..<3 {
            openServers(); cells.element(boundBy: index).tap(); app.buttons["vpn013.routing.next"].tap()
            XCTAssertEqual(only.value as? String, index < 2 ? "1" : "0")
            XCTAssertEqual(bypass.value as? String, "0")
            if index == 0 { only.tap(); app.buttons["vpn013.services.save"].tap() }
            else { app.navigationBars.buttons.element(boundBy: 0).tap(); app.navigationBars.buttons.element(boundBy: 0).tap() }
        }
        capture("wg-services-unselected-unchanged-no-vpn-started")
    }
    func testProxyRowsMatchAmneziaWGLayoutTapSwitchesHoldOpensConfiguration() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-hold-ping-for-cancellation"]
        app.launch()
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            app.buttons["vpn013.proxy.add"].tap(); app.buttons["vpn013.proxy.import.check"].tap()
            XCTAssertTrue(app.alerts["Серверов: 1"].waitForExistence(timeout: 5)); app.alerts.buttons["Добавить"].tap()
            let row = app.tables.cells.containing(.staticText, identifier: "Demo server").firstMatch
            XCTAssertTrue(row.waitForExistence(timeout: 8))
            // The same check-all control and latency column as AmneziaWG.
            let check = app.buttons["vpn013.proxy.check-ping"]
            XCTAssertTrue(check.isHittable); XCTAssertTrue(check.isEnabled)
            let latency = row.staticTexts["vpn013.proxy.latency"]
            XCTAssertTrue(latency.exists); XCTAssertEqual(latency.label, "Задержка ещё не измерена")
            XCTAssertTrue(app.staticTexts["vpn013.proxy.profile-count"].exists)
            check.tap()
            XCTAssertTrue(app.buttons["Остановить проверку"].waitForExistence(timeout: 3))
            XCTAssertTrue(app.staticTexts["vpn013.proxy.ping-explanation"].label.hasPrefix("Проверяем пинг адресов"))
            check.tap()
            XCTAssertTrue(app.staticTexts["vpn013.proxy.ping-explanation"].label.hasPrefix("Проверка остановлена"))
            XCTAssertNotEqual(row.staticTexts["vpn013.proxy.latency"].label, "Задержка: …", "A cancelled check keeps no placeholder value")
            // The simulator refuses a real VPN start. Its controlled start
            // error distinguishes the switch action from opening details.
            let power = row.switches["vpn013.proxy.switch"]
            XCTAssertTrue(power.exists); XCTAssertEqual(power.value as? String, "0")
            power.tap()
            XCTAssertTrue(app.alerts["Действие не завершено"].waitForExistence(timeout: 5))
            XCTAssertFalse(app.cells["vpn013.proxy.power"].exists); app.alerts.buttons["Понятно"].tap()
            XCTAssertEqual(row.switches["vpn013.proxy.switch"].value as? String, "0", "A refused start must not leave the switch on")
            // A short tap anywhere on the row is the same switch action.
            row.staticTexts["Demo server"].tap()
            XCTAssertTrue(app.alerts["Действие не завершено"].waitForExistence(timeout: 5))
            XCTAssertFalse(app.cells["vpn013.proxy.power"].exists); app.alerts.buttons["Понятно"].tap()
            row.staticTexts["Demo server"].press(forDuration: 2.5); XCTAssertTrue(app.cells["vpn013.proxy.power"].waitForExistence(timeout: 5))
            XCTAssertFalse(app.alerts["Действие не завершено"].exists)
            capture("row-" + kind + "-hold-opens-configuration")
            app.navigationBars.buttons.element(boundBy: 0).tap()
        }
    }
    func testRoutingSelectsMultipleServersAndPreservesUnselected() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-routing-roster"]
        app.launch()
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            app.buttons["vpn013.proxy.add"].tap(); app.buttons["vpn013.proxy.import.check"].tap()
            XCTAssertTrue(app.alerts["Серверов: 3"].waitForExistence(timeout: 5)); app.alerts.buttons["Добавить"].tap()
            app.buttons["vpn013.settings"].tap(); app.buttons["vpn013.settings.routing"].tap()
            let next = app.buttons["vpn013.routing.next"]
            let all = app.buttons["vpn013.routing.select-all"]
            XCTAssertTrue(next.waitForExistence(timeout: 5)); XCTAssertFalse(next.isEnabled)
            let cells = app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@", "vpn013.routing.server."))
            XCTAssertEqual(cells.count, 3)
            all.tap(); XCTAssertEqual(next.label, "Далее (3)")
            all.tap(); XCTAssertFalse(next.isEnabled)
            cells.element(boundBy: 0).tap(); cells.element(boundBy: 1).tap()
            XCTAssertEqual(next.label, "Далее (2)"); capture("routing-" + kind + "-two-selected-of-three")
            next.tap(); app.buttons["vpn013.proxy.routing.mode"].tap(); app.buttons["Выбранное — напрямую"].tap()
            let networks = app.textViews["IP-сети"]
            for _ in 0..<5 { if networks.isHittable { break }; app.scrollViews.firstMatch.swipeUp() }
            networks.tap(); networks.typeText("192.0.2.0/24")
            app.buttons["vpn013.proxy.routing.save"].tap()
            XCTAssertTrue(next.waitForExistence(timeout: 8))
            for index in 0..<3 {
                if all.label == "Снять выбор" { all.tap() } else { all.tap(); all.tap() }
                cells.element(boundBy: index).tap(); next.tap()
                let expected = index < 2 ? "Выбранное — напрямую" : "Весь трафик через VPN"
                XCTAssertEqual(app.buttons["vpn013.proxy.routing.mode"].value as? String, expected)
                XCTAssertEqual(app.textViews["IP-сети"].value as? String, index < 2 ? "192.0.2.0/24" : "")
                app.navigationBars.buttons.element(boundBy: 0).tap()
            }
            capture("routing-" + kind + "-unselected-profile-unchanged")
            app.navigationBars.buttons.element(boundBy: 0).tap(); app.buttons["vpn013.settings.done"].tap()
        }
    }
    private func openUpdatesFromSettings(_ app: XCUIApplication) {
        XCTAssertFalse(app.buttons["vpn013.updates"].exists, "AmneziaWG updates belong in Settings")
        let settings = app.buttons["vpn013.settings"]
        XCTAssertTrue(settings.waitForExistence(timeout: 20)); settings.tap()
        let update = app.buttons["vpn013.settings.update-app"]
        XCTAssertTrue(update.waitForExistence(timeout: 5))
        for _ in 0..<5 { if update.isHittable { break }; app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(update.isHittable); update.tap()
    }
    func testPowerTrafficAndPingPanelPresentInEveryProxySection() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-hold-ping-for-cancellation"]
        app.launch()
        app.tabBars.buttons["vpn013.kind.amneziawg"].tap()
        XCTAssertFalse(app.buttons["vpn013.current-power"].isHittable, "Connection controls start inside the popup")
        openConnectionPopup(app, title: "AmneziaWG")
        XCTAssertTrue(app.buttons["vpn013.current-power"].waitForExistence(timeout: 8))
        XCTAssertTrue(app.buttons["vpn013.connection-popup.ping"].exists)
        closeConnectionPopup(app)
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            let power = app.buttons["vpn013.proxy.current.power"]
            let ping = app.buttons["vpn013.proxy.current.ping"]
            XCTAssertFalse(power.isHittable, "Connection controls start inside the popup")
            openConnectionPopup(app, title: kind == "happ" ? "Happ" : kind == "incy" ? "INCY" : "BlackTemple")
            XCTAssertTrue(power.waitForExistence(timeout: 8)); XCTAssertFalse(power.isEnabled)
            XCTAssertTrue(ping.exists); XCTAssertFalse(ping.isEnabled)
            closeConnectionPopup(app)
            app.buttons["vpn013.proxy.add"].tap()
            // The sheet's dismissal can swallow the first tap; retry once.
            if !app.buttons["vpn013.proxy.import.check"].waitForExistence(timeout: 5) { app.buttons["vpn013.proxy.add"].tap() }
            app.buttons["vpn013.proxy.import.check"].tap()
            XCTAssertTrue(app.alerts["Серверов: 1"].waitForExistence(timeout: 5))
            app.alerts.buttons["Добавить"].tap()
            XCTAssertTrue(app.tables.cells.staticTexts["Demo server"].waitForExistence(timeout: 8))
            openConnectionPopup(app, title: kind == "happ" ? "Happ" : kind == "incy" ? "INCY" : "BlackTemple")
            XCTAssertTrue(power.isEnabled); XCTAssertTrue(ping.isEnabled)
            XCTAssertEqual(app.staticTexts["vpn013.proxy.current.name"].label, "Demo server")
            XCTAssertEqual(app.staticTexts["vpn013.proxy.current.status"].label, "Не подключено")
            capture("proxy-panel-" + kind + "-power-and-ping-offline")
            ping.tap()
            XCTAssertTrue(app.buttons["Отменить проверку пинга"].waitForExistence(timeout: 3))
            ping.tap()
            XCTAssertEqual(app.staticTexts["vpn013.proxy.current.status"].label, "Не подключено", "Ping must not activate a VPN")
            closeConnectionPopup(app)
        }
    }
    func testTrafficSummaryUsesAdaptiveUnits() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-unified", "--vpn013-test-cross-runtime", "--vpn013-test-cross-traffic", "--vpn013-test-auto-reset"]
        app.launch()
        let current = app.staticTexts["vpn013.cross.current"]
        XCTAssertTrue(current.waitForExistence(timeout: 20))
        XCTAssertTrue(current.label.contains("2 ГБ"))
        XCTAssertFalse(current.label.contains("2000000000"))
        let measured = NSPredicate { _, _ in current.label.contains("Скорость: ↓ 2 Мбит/с") }
        expectation(for: measured, evaluatedWith: current)
        waitForExpectations(timeout: 12)
        XCTAssertTrue(current.label.contains("Тестовые данные"))
        capture("traffic-rounded-gigabytes-and-megabits-synthetic-no-vpn")
    }

    func testSettingsReachableInEveryProxySectionAndPreserveImportText() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch()
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            let settings = app.buttons["vpn013.settings"]
            XCTAssertTrue(settings.waitForExistence(timeout: 8)); settings.tap()
            XCTAssertTrue(app.buttons["vpn013.settings.routing"].waitForExistence(timeout: 5))
            XCTAssertTrue(app.buttons["vpn013.settings.refresh-configurations"].exists)
            XCTAssertTrue(app.buttons["vpn013.settings.update-app"].exists)
            XCTAssertTrue(app.buttons["vpn013.view-log"].exists)
            capture("settings-" + kind + "-routing-refresh-journal")
            app.buttons["vpn013.settings.done"].tap()
            app.buttons["vpn013.proxy.add"].tap()
            let input = app.textViews["vpn013.proxy.import.text"]
            XCTAssertTrue(input.waitForExistence(timeout: 5))
            let original = input.value as? String
            XCTAssertFalse(original?.isEmpty ?? true)
            app.buttons["vpn013.settings"].tap()
            XCTAssertTrue(app.buttons["vpn013.settings.done"].waitForExistence(timeout: 5))
            app.buttons["vpn013.settings.done"].tap()
            XCTAssertEqual(input.value as? String, original)
            app.navigationBars.buttons.element(boundBy: 0).tap()
        }
    }
    func testSharedOwnerProxyZIPSelectsIncyAndPreviewsProfile() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-owner-proxy-zip"]
        app.launch()
        let preview = app.alerts["Серверов: 1"]
        XCTAssertTrue(preview.waitForExistence(timeout: 20))
        XCTAssertTrue(preview.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "INCY")).firstMatch.exists)
        preview.buttons["Добавить"].tap()
        XCTAssertTrue(app.tables.cells.staticTexts["Example"].waitForExistence(timeout: 20))

        // A URL supplied inside a ZIP must not initiate a request before the
        // owner confirms its destination. The test transport intercepts all
        // requests; the address and token below are synthetic.
        app.terminate()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-owner-proxy-zip-url"]
        app.launch()
        let firstConfirmation = app.alerts["Загрузить подписку?"]
        XCTAssertTrue(firstConfirmation.waitForExistence(timeout: 20))
        XCTAssertTrue(firstConfirmation.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "127.0.0.1:9443")).firstMatch.exists)
        XCTAssertFalse(firstConfirmation.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "synthetic-token")).firstMatch.exists)
        firstConfirmation.buttons["Отмена"].tap()
        let firstCount = app.staticTexts["vpn013.zip.fixture.request-count"]
        XCTAssertTrue(firstCount.waitForExistence(timeout: 5))
        XCTAssertEqual(firstCount.label, "Запросов: 0")
        let unexpectedRequest = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label != %@", "Запросов: 0"), object: firstCount)
        unexpectedRequest.isInverted = true
        XCTAssertEqual(XCTWaiter.wait(for: [unexpectedRequest], timeout: 2), .completed)

        app.terminate(); app.launch()
        let confirmation = app.alerts["Загрузить подписку?"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 20))
        confirmation.buttons["Загрузить"].tap()
        let urlPreview = app.alerts["Серверов: 1"]
        XCTAssertTrue(urlPreview.waitForExistence(timeout: 20))
        urlPreview.buttons["Отмена"].tap()
        let count = app.staticTexts["vpn013.zip.fixture.request-count"]
        XCTAssertTrue(count.waitForExistence(timeout: 5))
        let received = NSPredicate(format: "label == %@", "Запросов: 1")
        XCTAssertEqual(XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: received, object: count)], timeout: 5), .completed)
    }
    func testInvitationReachableFromEveryProxySectionWithoutSharingProfiles() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch()
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            let invite = app.buttons["vpn013.invite"]
            XCTAssertTrue(invite.waitForExistence(timeout: 8)); invite.tap()
            XCTAssertTrue(app.navigationBars["Пригласить друга"].waitForExistence(timeout: 5))
            let message = app.staticTexts["vpn013.invite.message"]
            XCTAssertTrue(message.waitForExistence(timeout: 5))
            XCTAssertTrue(message.label.contains("https://vpn013.com/"))
            XCTAssertTrue(message.label.contains("https://t.me/vpn013_com_bot"))
            XCTAssertFalse(message.label.contains("vless://"))
            XCTAssertTrue(app.buttons["vpn013.invite.personal"].exists)
            XCTAssertTrue(app.buttons["vpn013.invite.share"].exists)
            capture("invite-" + kind + "-public-links-no-profile-data")
            app.navigationBars.buttons.element(boundBy: 0).tap()
        }
    }
    func testNativeRussianIPRouteObjectsPreserveVPNAndPeers() {
        let app=XCUIApplication()
        app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU","--vpn013-test-count","2","--vpn013-test-russian-routes"]
        app.launch()
        openConnectionPopup(app, title: "AmneziaWG")
        let policy=app.staticTexts["vpn013.routing-policy"]
        XCTAssertTrue(policy.waitForExistence(timeout:20))
        XCTAssertEqual(policy.value as? String,"8671 IPv4 / 2167 IPv6; original peers retained")
        capture("native-russian-ip-settings-objects-not-physical-traffic")
    }
    func capture(_ name:String) { let a=XCTAttachment(screenshot:XCUIScreen.main.screenshot());a.name=name;a.lifetime = .keepAlways;add(a) }
    private func openConnectionPopup(_ app: XCUIApplication, title: String = "AmneziaWG") {
        let open = app.buttons["vpn013.connection-popup.open"]
        XCTAssertTrue(open.waitForExistence(timeout: 15)); open.tap()
        let heading = app.staticTexts["vpn013.connection-popup.title"]
        XCTAssertTrue(heading.waitForExistence(timeout: 5)); XCTAssertEqual(heading.label, title)
    }
    private func closeConnectionPopup(_ app: XCUIApplication) {
        let close = app.buttons["vpn013.connection-popup.close"]
        XCTAssertTrue(close.waitForExistence(timeout: 5)); close.tap()
    }
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
        addUIInterruptionMonitor(withDescription: "Notification authorization") { alert in
            for title in ["Allow", "Разрешить", "Don’t Allow", "Не разрешать"] {
                let button = alert.buttons[title]
                if button.exists { button.tap(); return true }
            }
            return false
        }
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-native-trial" + variant]
        app.launch(); XCTAssertTrue(app.buttons["vpn013.add-profile"].waitForExistence(timeout:20)); return app
    }
    private func startNativeTrial(_ app: XCUIApplication) {
        app.buttons["vpn013.add-profile"].tap()
        // A tap during the previous alert's dismissal can be swallowed; retry once.
        if !app.buttons["Три дня теста бесплатно"].waitForExistence(timeout:5) { app.buttons["vpn013.add-profile"].tap() }
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
        let choice = app.alerts["Уточните версию AmneziaWG"]
        XCTAssertTrue(choice.waitForExistence(timeout: 20))
        choice.buttons["AmneziaWG 2.0 / 3.1"].tap()
        let secondChoice = choice.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Нидерланды")).firstMatch
        XCTAssertTrue(secondChoice.waitForExistence(timeout: 8))
        choice.buttons["AmneziaWG 2.0 / 3.1"].tap()
        XCTAssertTrue(app.staticTexts["Швеция"].waitForExistence(timeout:20))
        XCTAssertEqual(app.alerts.count,0)
        assertProfileCount(app, 13)
        for name in ["Беларусь","Германия","Германия 2","Грузия","Испания","Нидерланды","Польша","Польша 2","США","Турция","Финляндия","Финляндия 2","Швеция"] {
            XCTAssertEqual(app.tables.cells.staticTexts.matching(identifier:name).count,1)
        }
        capture("04-shared-zip-26-files-13-imported")
        func openAuthenticatedEditor() -> Bool {
            let edit = app.buttons["vpn013.edit-profile"]
            guard edit.waitForExistence(timeout: 5) else { XCTFail("Profile editor button is unavailable"); capture("zip-editor-button-unavailable"); return false }
            edit.tap()
            // Do not swipe the underlying profile while the system is still
            // authenticating: wait for the actual editor before interacting.
            guard app.buttons["vpn013.cancel-profile-edit"].waitForExistence(timeout: 30) else {
                capture("zip-editor-authentication-did-not-open")
                XCTFail("Authenticated profile editor did not open")
                return false
            }
            return true
        }
        app.tables.cells.staticTexts["Испания"].press(forDuration: 2.5)
        guard openAuthenticatedEditor() else { return }
        let version = app.textFields["vpn013.awg15.version"]
        for _ in 0..<8 where !version.isHittable { app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(version.waitForExistence(timeout: 5))
        XCTAssertEqual(version.value as? String, "1.5")
        capture("04a-legacy-profile-version-visible")
        app.buttons["vpn013.cancel-profile-edit"].tap()
        app.navigationBars["Испания"].buttons.element(boundBy: 0).tap()
        // The I-only example is ambiguous. Choose 1.5 explicitly, save it and
        // reopen the editor to prove the user's choice is actually persisted.
        app.tables.cells.staticTexts["Беларусь"].press(forDuration: 2.5)
        guard openAuthenticatedEditor() else { return }
        for _ in 0..<8 where !version.isHittable { app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(version.waitForExistence(timeout: 5))
        XCTAssertEqual(app.textFields.matching(identifier: "vpn013.awg15.version").count, 1, "Reused peer fields must not inherit the version identifier")
        version.tap(); version.typeText("1.5")
        app.buttons["vpn013.save-profile-edit"].tap()
        guard openAuthenticatedEditor() else { return }
        for _ in 0..<8 where !version.isHittable { app.tables.firstMatch.swipeUp() }
        XCTAssertEqual(version.value as? String, "1.5")
        capture("04b-explicit-legacy-choice-saved")
        app.buttons["vpn013.cancel-profile-edit"].tap()
        app.navigationBars["Беларусь"].buttons.element(boundBy: 0).tap()
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
    func testThirtyAndFiftyPersonalServers() {
        createFromPersonalServers(count:30, label:"30 серверов")
        XCUIApplication().terminate()
        createFromPersonalServers(count:50, label:"50 серверов")
        XCUIApplication().terminate()
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "51"]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 1"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        app.buttons["Создать режим Авто"].tap()
        let error = app.alerts["Авто не создано"]
        XCTAssertTrue(error.waitForExistence(timeout:5))
        error.buttons["Понятно"].tap()
        assertProfileCount(app, 51)
        capture("dynamic-51-servers-rejected-with-profiles-preserved")
    }
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
        openUpdatesFromSettings(app)
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
        // A short tap acts like the switch and never opens details.
        profile.staticTexts["Личный сервер 1"].tap()
        XCTAssertFalse(app.navigationBars["Личный сервер 1"].waitForExistence(timeout:2), "Only a two-second hold opens details")
        if app.alerts.firstMatch.waitForExistence(timeout:1) { app.alerts.firstMatch.buttons.firstMatch.tap() }
        profile.staticTexts["Личный сервер 1"].press(forDuration: 2.5)
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
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-hold-ping-for-cancellation"]
        app.launch()
        let button = app.buttons["vpn013.check-ping"]
        XCTAssertTrue(button.waitForExistence(timeout:20))
        button.tap()
        XCTAssertTrue(app.buttons["Остановить проверку"].waitForExistence(timeout:2))
        button.tap()
        let stopped = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", "Проверить пинг"), object: button)
        XCTAssertEqual(XCTWaiter.wait(for: [stopped], timeout: 8), .completed, "Cancellation must restore the idle action")
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
        let autoSwitch = auto.switches.firstMatch
        autoSwitch.tap()
        let active = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '1'"), object: autoSwitch)
        let activeResult = XCTWaiter.wait(for: [active], timeout: 20)
        XCTAssertEqual(activeResult, .completed, "Synthetic Auto must activate before opening its current-server card")
        guard activeResult == .completed else { capture("20-auto-activation-failed-synthetic"); return }
        // Exercise simulator foreground refresh without treating its inactive system stub as a real VPN state.
        XCUIDevice.shared.press(.home)
        app.activate()
        let restored = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '1'"), object: autoSwitch)
        let restoredResult = XCTWaiter.wait(for: [restored], timeout: 20)
        XCTAssertEqual(restoredResult, .completed, "Synthetic Auto must survive simulator foreground refresh")
        guard restoredResult == .completed else { capture("20-auto-foreground-failed-synthetic"); return }
        openConnectionPopup(app)
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout:8))
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].waitForExistence(timeout:8))
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Дом", "Card must show actual Auto member, not its seed")
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].label.contains("127.0.0.1:4444"))
        XCTAssertTrue(app.staticTexts["vpn013.current-traffic"].exists)
        XCTAssertTrue(ping.isEnabled && ping.isHittable)
        if ping.frame.height + 0.001 < 44 { capture("20-current-ping-short-visible-target") }
        XCTAssertGreaterThanOrEqual(ping.frame.height + 0.001, 44, "Allow only floating-point coordinate rounding; the 44-point target remains required")
        ping.tap()
        let result = app.staticTexts.matching(NSPredicate(format:"identifier == %@ AND label ENDSWITH %@", "vpn013.current-ping-result", "мс")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout:10), "Current-server button must show a real loopback echo result")
        capture("20-auto-first-current-member-real-loopback-ping-synthetic-vpn")
        closeConnectionPopup(app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "1", "Current-server Ping cannot switch off Auto")
        auto.switches.firstMatch.tap()
        openConnectionPopup(app)
        XCTAssertFalse(ping.isHittable, "No current-server action after VPN is off")
    }

    func testManualCurrentServerPingAndInfo() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-current-card", "--vpn013-test-ping-loopback"]
        app.launch()
        let profile = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:20))
        profile.switches.firstMatch.tap()
        openConnectionPopup(app)
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(app.staticTexts["vpn013.current-endpoint"].waitForExistence(timeout:8))
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 1")
        XCTAssertTrue(ping.isHittable && ping.isEnabled)
        ping.tap()
        let result = app.staticTexts.matching(NSPredicate(format:"identifier == %@ AND label ENDSWITH %@", "vpn013.current-ping-result", "мс")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout:10))
        capture("21-current-manual-server-real-loopback-ping-synthetic-vpn")
        XCUIDevice.shared.orientation = .landscapeLeft
        capture("22-current-manual-server-landscape-synthetic-vpn")
        XCUIDevice.shared.orientation = .portrait
        closeConnectionPopup(app)
        XCTAssertEqual(profile.switches.firstMatch.value as? String, "1")
        let portraitReady = XCTNSPredicateExpectation(predicate: NSPredicate(format: "hittable == true AND value == '1'"), object: profile.switches.firstMatch)
        XCTAssertEqual(XCTWaiter.wait(for: [portraitReady], timeout: 5), .completed)
        profile.switches.firstMatch.tap()
        let disconnected = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == '0'"), object: profile.switches.firstMatch)
        XCTAssertEqual(XCTWaiter.wait(for: [disconnected], timeout: 5), .completed)
        openConnectionPopup(app)
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
        openConnectionPopup(app)
        let proof = app.staticTexts["vpn013.current-proof"]
        let received = XCTNSPredicateExpectation(predicate: NSPredicate(format:"label == %@", "Данные рукопожатия получены"), object: proof)
        XCTAssertEqual(XCTWaiter.wait(for:[received], timeout:8), .completed)
        XCTAssertTrue(app.staticTexts["vpn013.current-handshake"].label.hasPrefix("Рукопожатие:"))
        XCTAssertFalse(app.staticTexts["vpn013.current-traffic"].label.contains("недоступна"))
        capture("manual-runtime-handshake-summary-synthetic-no-internet-proof")
        closeConnectionPopup(app)
        XCTAssertEqual(profile.switches.firstMatch.value as? String, "1")
    }

    private func checkManualPingWithoutRuntime(_ fixture: String, captureName: String) {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", fixture, "--vpn013-test-ping-loopback"]
        app.launch()
        let profile = app.tables.cells.containing(.staticText, identifier:"Личный сервер 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:20))
        // The cell may be rebuilt during list updates. Resolve the uniquely
        // named switch directly so a stale cell snapshot cannot supply an
        // invalid activation point while still keeping a real tap and checks.
        let manualSwitch = app.switches["Личный сервер 1"]
        XCTAssertTrue(manualSwitch.waitForExistence(timeout:20))
        let readyToConnect = XCTNSPredicateExpectation(predicate: NSPredicate(format:"hittable == true AND enabled == true AND value == '0'"), object: manualSwitch)
        XCTAssertEqual(XCTWaiter.wait(for:[readyToConnect], timeout:20), .completed, "The synthetic switch must be ready and off before activation")
        manualSwitch.tap()
        // A simulator system banner (for example an Apple Intelligence notice)
        // can swallow the first tap. Retry only when the switch is still off and
        // hittable; an app that fails to connect still fails the wait below.
        let firstTap = XCTNSPredicateExpectation(predicate: NSPredicate(format:"value == '1'"), object: manualSwitch)
        if XCTWaiter.wait(for:[firstTap], timeout:8) != .completed,
           (manualSwitch.value as? String) == "0", manualSwitch.isHittable {
            manualSwitch.tap()
        }
        let connected = XCTNSPredicateExpectation(predicate: NSPredicate(format:"value == '1'"), object: manualSwitch)
        let connectedResult = XCTWaiter.wait(for:[connected], timeout:20)
        XCTAssertEqual(connectedResult, .completed, "The synthetic connection must become active before the popup is opened")
        guard connectedResult == .completed else {
            capture("manual-runtime-fixture-failed-immediately-after-activation")
            return
        }
        if fixture == "--vpn013-test-current-card-timeout" {
            // The simulator has no real system VPN session. Exercise the
            // foreground status refresh while keeping this model-only fixture active.
            XCUIDevice.shared.press(.home)
            app.activate()
            let restored = XCTNSPredicateExpectation(predicate: NSPredicate(format:"value == '1'"), object: manualSwitch)
            let restoredResult = XCTWaiter.wait(for:[restored], timeout:20)
            XCTAssertEqual(restoredResult, .completed, "The active synthetic connection must survive a foreground refresh")
            guard restoredResult == .completed else {
                capture("manual-runtime-fixture-failed-after-foreground")
                return
            }
        }
        openConnectionPopup(app)
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
        capture(captureName)
        closeConnectionPopup(app)
        XCTAssertEqual(manualSwitch.value as? String, "1", "Ping and refresh must not replace the running VPN")
        manualSwitch.tap()
        openConnectionPopup(app)
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
        openConnectionPopup(app)
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout:8))
        XCTAssertFalse(ping.isEnabled, "Unknown Auto member cannot be replaced by its saved seed")
        XCTAssertEqual(app.staticTexts["vpn013.current-endpoint"].label, "Текущий сервер пока недоступен")
        capture("25-auto-unknown-member-no-seed-ping-synthetic-vpn")
        closeConnectionPopup(app)
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
        openConnectionPopup(app)
        let power = waitForPowerValue("Выключен", in: app)
        XCTAssertTrue(power.isEnabled && power.isHittable)
        XCTAssertGreaterThanOrEqual(power.frame.width, 44)
        XCTAssertEqual(power.frame.width, power.frame.height, accuracy: 0.5)
        capture("26a-current-power-off-synthetic")
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 1")
        capture("26b-current-power-on-without-runtime-synthetic")
        closeConnectionPopup(app)
        XCTAssertEqual(first.switches.firstMatch.value as? String, "1")
        openConnectionPopup(app)
        power.tap()
        _ = waitForPowerValue("Выключен", in: app)
        closeConnectionPopup(app)
        XCTAssertEqual(first.switches.firstMatch.value as? String, "0")
        second.switches.firstMatch.tap()
        openConnectionPopup(app)
        _ = waitForPowerValue("Включён", in: app)
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 2")
        power.tap()
        _ = waitForPowerValue("Выключен", in: app)
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Личный сервер 2")
        closeConnectionPopup(app)
        XCTAssertEqual(second.switches.firstMatch.value as? String, "0")
        openConnectionPopup(app)
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        closeConnectionPopup(app)
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
        openConnectionPopup(app)
        let power = waitForPowerValue("Выключен", in: app)
        XCTAssertEqual(app.staticTexts["vpn013.current-name"].label, "Авто · 2 сервера")
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        let ping = app.buttons["vpn013.current-ping"]
        XCTAssertTrue(ping.waitForExistence(timeout: 8))
        XCTAssertFalse(ping.isEnabled, "Unknown Auto member must still not ping a saved seed")
        XCTAssertTrue(power.isEnabled && power.isHittable, "Power depends on the connection, not runtime statistics")
        capture("27-current-power-auto-without-member-statistics-synthetic")
        closeConnectionPopup(app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "1")
        openConnectionPopup(app)
        power.tap()
        _ = waitForPowerValue("Выключен", in: app)
        closeConnectionPopup(app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "0")
        openConnectionPopup(app)
        power.tap()
        _ = waitForPowerValue("Включён", in: app)
        closeConnectionPopup(app)
        XCTAssertEqual(auto.switches.firstMatch.value as? String, "1")
    }

    func testCurrentPowerButtonEmptyAndLargeType() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "0"]
        app.launch()
        openConnectionPopup(app)
        let emptyPower = waitForPowerValue("Выключен", in: app)
        XCTAssertFalse(emptyPower.isEnabled, "No profile may be invented or connected from an empty list")
        capture("28a-current-power-empty-disabled-synthetic")
        app.terminate()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU",
            "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
            "--vpn013-test-count", "2", "--vpn013-test-current-card", "--vpn013-test-start-current"]
        app.launch()
        openConnectionPopup(app)
        let power = waitForPowerValue("Включён", in: app)
        for _ in 0..<5 {
            if power.isHittable { break }
            app.scrollViews.firstMatch.swipeUp()
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
        openConnectionPopup(app)
        let power = waitForPowerValue("Изменение подключения", in: app)
        XCTAssertFalse(power.isEnabled, "A second activation must not be submitted during a transition")
        XCTAssertFalse(app.buttons["vpn013.automatic-mode"].isEnabled, "Auto preference cannot race the prepared connection payload")
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == %@", "Подключение…")).firstMatch.exists)
        capture("29-current-power-connecting-disabled-synthetic")
    }

    func testUnifiedSectionsImportAndIsolation() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch()
        for kind in ["happ", "incy", "blacktemple"] {
            let tab = app.tabBars.buttons["vpn013.kind." + kind]
            XCTAssertTrue(tab.waitForExistence(timeout: 15)); tab.tap()
            XCTAssertTrue(app.tables.cells.staticTexts["Добавить конфигурацию"].waitForExistence(timeout: 8))
            app.buttons["vpn013.proxy.add"].tap()
            let draft = app.textViews["vpn013.proxy.import.text"]
            XCTAssertTrue(draft.waitForExistence(timeout: 5))
            XCTAssertTrue(app.buttons["vpn013.proxy.import.paste"].exists)
            XCTAssertTrue(app.buttons["vpn013.proxy.import.qr"].exists)
            let original = draft.value as? String
            draft.tap()
            XCTAssertTrue(app.toolbars.buttons["Готово"].waitForExistence(timeout: 5))
            app.toolbars.buttons["Готово"].tap()
            XCTAssertEqual(draft.value as? String, original, "Closing the keyboard must preserve the person's key")
            XCUIDevice.shared.press(.home); app.activate()
            XCTAssertTrue(draft.waitForExistence(timeout: 8))
            XCTAssertEqual(draft.value as? String, original, "Returning from another app must preserve the input and selected section")
            let currentTab = XCTNSPredicateExpectation(predicate: NSPredicate(format:"selected == true"), object: tab)
            XCTAssertEqual(XCTWaiter.wait(for:[currentTab], timeout:15), .completed, "Returning from another app must keep the same protocol section")
            let checkReady = XCTNSPredicateExpectation(predicate: NSPredicate(format:"hittable == true"), object: app.buttons["vpn013.proxy.import.check"])
            XCTAssertEqual(XCTWaiter.wait(for:[checkReady], timeout:15), .completed, "The existing import action must become available after returning")
            XCTAssertTrue(app.buttons["vpn013.proxy.import.check"].isHittable)
            app.buttons["vpn013.proxy.import.check"].tap()
            XCTAssertTrue(app.alerts["Серверов: 1"].waitForExistence(timeout: 5))
            app.alerts.buttons["Добавить"].tap()
            XCTAssertTrue(app.tables.cells.staticTexts["Demo server"].waitForExistence(timeout: 8))
            XCTAssertEqual(tab.label, kind == "happ" ? "Happ" : kind == "incy" ? "INCY" : "BlackTemple", "Loading a section must not rename its protocol tab to VPN013")
            capture("unified-" + kind + "-imported-synthetic")
        }
        app.tabBars.buttons["vpn013.kind.amneziawg"].tap()
        XCTAssertFalse(app.tables.cells.staticTexts["Demo server"].exists)
        capture("unified-awg-existing-profiles-preserved")
    }

    func testUnifiedInvalidImportKeepsProfiles() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch(); app.tabBars.buttons["vpn013.kind.happ"].tap(); app.buttons["vpn013.proxy.add"].tap()
        let input = app.textViews["vpn013.proxy.import.text"]
        XCTAssertTrue(input.waitForExistence(timeout: 8)); input.tap()
        input.press(forDuration: 1)
        if app.menuItems["Выбрать всё"].exists { app.menuItems["Выбрать всё"].tap(); input.typeText("invalid-profile") }
        else { input.typeText("\ninvalid-profile") }
        app.buttons["vpn013.proxy.import.check"].tap()
        XCTAssertTrue(app.alerts["Не удалось добавить"].waitForExistence(timeout: 5))
        capture("unified-invalid-import-explains-error-synthetic")
    }

    func testUnifiedRoutingPersistsTypedPolicy() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch(); app.tabBars.buttons["vpn013.kind.incy"].tap(); app.buttons["vpn013.proxy.add"].tap()
        app.buttons["vpn013.proxy.import.check"].tap(); app.alerts.buttons["Добавить"].tap()
        let row = app.tables.cells.containing(.staticText, identifier: "Demo server").firstMatch; XCTAssertTrue(row.waitForExistence(timeout: 8)); row.staticTexts["Demo server"].press(forDuration: 2.5)
        XCTAssertTrue(app.tables.cells.staticTexts["Маршрутизация"].waitForExistence(timeout: 5)); app.tables.cells.staticTexts["Маршрутизация"].tap()
        app.buttons["vpn013.proxy.routing.mode"].tap()
        app.buttons["Выбранное — напрямую"].tap()
        let domains = app.textViews["Домены"]; domains.tap(); domains.typeText("example.invalid")
        app.navigationBars.buttons["Сохранить"].tap()
        XCTAssertTrue(app.staticTexts["Выбранное — напрямую"].waitForExistence(timeout: 5))
        capture("unified-routing-domain-policy-synthetic")
    }

    func testUnifiedRemembersSelectedSection() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified"]
        app.launch(); let selected = app.tabBars.buttons["vpn013.kind.blacktemple"]
        XCTAssertTrue(selected.waitForExistence(timeout: 15)); selected.tap(); app.terminate(); app.launch()
        XCTAssertTrue(app.tabBars.buttons["vpn013.kind.blacktemple"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.tabBars.buttons["vpn013.kind.blacktemple"].isSelected)
        capture("unified-selected-section-restored-synthetic")
    }

    func testAutomaticModeDefaultSharedAndPersistent() {
        let app = XCUIApplication()
        let arguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-automatic"]
        app.launchArguments = arguments + ["--vpn013-test-auto-reset"]
        app.launch(); app.tabBars.buttons["vpn013.kind.happ"].tap()
        let toggle = app.buttons["vpn013.automatic-mode"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 10)); XCTAssertEqual(toggle.value as? String, "1")
        XCTAssertLessThanOrEqual(toggle.frame.height, 44); XCTAssertLessThanOrEqual(toggle.frame.width, 44)
        XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label == %@", "Лучший ответ при запуске, сравнение каждые 5 минут. Если раздел не работает — другие загруженные конфигурации. Выключите для ручного выбора.")).firstMatch.exists)
        capture("automatic-default-on-happ-empty-no-vpn-synthetic")
        toggle.tap(); XCTAssertEqual(toggle.value as? String, "0")
        for kind in ["incy", "blacktemple", "amneziawg"] {
            app.tabBars.buttons["vpn013.kind." + kind].tap()
            let shared = app.buttons["vpn013.automatic-mode"]
            XCTAssertTrue(shared.waitForExistence(timeout: 6)); XCTAssertEqual(shared.value as? String, "0")
        }
        app.terminate(); app.launchArguments = arguments; app.launch()
        app.tabBars.buttons["vpn013.kind.blacktemple"].tap()
        XCTAssertTrue(app.buttons["vpn013.automatic-mode"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.buttons["vpn013.automatic-mode"].value as? String, "0")
        app.buttons["vpn013.automatic-mode"].tap()
        XCTAssertEqual(app.buttons["vpn013.automatic-mode"].value as? String, "1")
        capture("automatic-restored-and-enabled-blacktemple-no-vpn-synthetic")
    }

    func testFullJSONImportsVisibleRosterWithoutBackupDuplicates() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-unified-json"]
        app.launch(); app.tabBars.buttons["vpn013.kind.happ"].tap(); app.buttons["vpn013.proxy.add"].tap()
        app.buttons["vpn013.proxy.import.check"].tap()
        XCTAssertTrue(app.alerts["Серверов: 3"].waitForExistence(timeout: 8))
        capture("full-json-three-visible-servers-without-backup-copies-synthetic")
        app.alerts.buttons["Добавить"].tap()
        for index in 0..<3 { XCTAssertTrue(app.tables.cells.staticTexts["Country \(index)"].waitForExistence(timeout: 8)) }
        XCTAssertFalse(app.tables.cells.staticTexts["node3.example.invalid"].exists)
        app.tabBars.buttons["vpn013.kind.incy"].tap()
        XCTAssertFalse(app.tables.cells.staticTexts["Country 0"].exists)
    }

    func testProxySubscriptionRosterRestoresDeletedAndPreservesOtherSources() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-subscription-roster"]
        app.launch(); app.tabBars.buttons["vpn013.kind.happ"].tap()
        let fixture = app.buttons["vpn013.subscription.fixture"]
        XCTAssertTrue(fixture.waitForExistence(timeout: 10)); fixture.tap()
        XCTAssertTrue(app.alerts["Проверка подписок пройдена"].waitForExistence(timeout: 25))
        capture("subscription-roster-restoration-and-source-isolation-synthetic-no-network")
    }

    func testProxyMissingRuntimeNeverDisplaysAutomaticSeedAsCurrentServer() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-unified", "--vpn013-test-proxy-connected-missing"]
        app.launch(); app.tabBars.buttons["vpn013.kind.happ"].tap(); app.buttons["vpn013.proxy.add"].tap()
        app.buttons["vpn013.proxy.import.check"].tap(); app.alerts.buttons["Добавить"].tap()
        let row = app.tables.cells.containing(.staticText, identifier: "Demo server").firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 8)); row.staticTexts["Demo server"].press(forDuration: 2.5)
        let endpoint = app.cells["vpn013.proxy.current-endpoint"]
        XCTAssertTrue(endpoint.waitForExistence(timeout: 8))
        let explanation = endpoint.staticTexts["VPN-расширение пока не вернуло текущий сервер"]
        XCTAssertTrue(explanation.waitForExistence(timeout: 8))
        XCTAssertFalse(endpoint.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "demo.example.invalid")).firstMatch.exists,
                       "A saved Auto seed is not proof of the selected member")
        capture("proxy-unknown-current-member-no-seed-fallback-synthetic-no-vpn")
    }

    func testCrossProtocolRuntimeUsesActualSectionAndGlobalStop() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-unified", "--vpn013-test-cross-runtime", "--vpn013-test-auto-reset"]
        app.launch()
        XCTAssertTrue(app.staticTexts["vpn013.cross.kind"].waitForExistence(timeout: 20))
        XCTAssertEqual(app.staticTexts["vpn013.cross.kind"].label, "Общее Авто · Happ")
        XCTAssertTrue(app.tabBars.buttons["Happ"].isSelected)
        XCTAssertTrue(app.staticTexts["vpn013.cross.current"].label.contains("reserve.example.invalid:443"))
        XCTAssertTrue(app.staticTexts["vpn013.cross.current"].label.contains("Тестовые данные"))
        for kind in ["INCY", "AmneziaWG", "BlackTemple", "Happ"] {
            app.tabBars.buttons[kind].tap()
            XCTAssertTrue(app.buttons["vpn013.cross.stop"].isHittable)
        }
        capture("cross-protocol-current-and-stop-synthetic-no-vpn")
        app.buttons["vpn013.cross.stop"].tap()
        XCTAssertFalse(app.buttons["vpn013.cross.stop"].exists)
        capture("cross-protocol-user-stopped-synthetic-no-vpn")
    }

    func testSubscriptionDuplicateImportAndRemovalPreserveForeignProfiles() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-sync", "--vpn013-test-ownership"]
        app.launch()
        openUpdatesFromSettings(app)
        let fixture = app.cells["vpn013.sync-fixture"]
        for _ in 0..<5 { if fixture.isHittable { break }; app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(fixture.isHittable)
        fixture.tap()
        XCTAssertTrue(app.staticTexts["OWNERSHIP_IMPORT_REMOVE_PROFILES_PRESERVED"].waitForExistence(timeout: 30))
    }

    func testCorruptRegistryRejectsPendingRemovalAndImport() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-ownership-corrupt"]
        app.launch()
        openUpdatesFromSettings(app)
        let fixture = app.cells["vpn013.sync-fixture"]
        for _ in 0..<5 { if fixture.isHittable { break }; app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(fixture.isHittable)
        fixture.tap()
        XCTAssertTrue(app.staticTexts["OWNERSHIP_CORRUPT_REJECTED_PROFILES_PRESERVED"].waitForExistence(timeout: 30))
    }

    func testUpdatesScreenAndOrderSynchronization() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2", "--vpn013-test-sync"]
        app.launch()
        openUpdatesFromSettings(app)
        XCTAssertTrue(app.staticTexts["Пока нет привязанных заявок"].waitForExistence(timeout:5))
        XCTAssertTrue(app.cells["vpn013.update-check"].exists)
        capture("17-updates-before-binding")
        let fixture = app.cells["vpn013.sync-fixture"]
        for _ in 0..<5 { if fixture.isHittable { break }; app.tables.firstMatch.swipeUp() }
        XCTAssertTrue(fixture.isHittable)
        fixture.tap()
        let passed = app.staticTexts.matching(NSPredicate(format: "label == %@", "Проверено: добавление, удаление, ключи, сторонний профиль и Авто · 3 сервера; восстановление удалённых, 10→20→15, Авто · 16 серверов")).firstMatch
        XCTAssertTrue(passed.waitForExistence(timeout:30))
        capture("18-order-sync-invariants-passed-synthetic")
        app.navigationBars["Обновления"].buttons["Готово"].tap()
        app.buttons["vpn013.settings.done"].tap()
        XCTAssertTrue(app.tables.cells.staticTexts["Managed 1"].waitForExistence(timeout:5))
        XCTAssertTrue(app.staticTexts["Профили · 17"].exists)
        XCTAssertTrue(app.tables.cells.staticTexts["Авто · 16 серверов"].exists)
        XCTAssertFalse(app.tables.cells.staticTexts["Личный сервер 1"].exists)
        XCTAssertTrue(app.tables.cells.staticTexts["Личный сервер 2"].exists)
        capture("19-updated-order-and-foreign-profile-preserved-synthetic")
    }
}
