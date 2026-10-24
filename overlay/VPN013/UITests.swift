import XCTest
final class AutoTunnelUITests:XCTestCase {
    func capture(_ name:String) { let a=XCTAttachment(screenshot:XCUIScreen.main.screenshot());a.name=name;a.lifetime = .keepAlways;add(a) }
    func testCreateAutomaticFromThirteenImportedFixtures() {
        let app=XCUIApplication();app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU"];app.launch()
        XCTAssertTrue(app.staticTexts["��������"].waitForExistence(timeout:20))
        capture("01-thirteen-servers-simulator-fixture")
        app.buttons["vpn013.add-profile"].tap()
        XCTAssertTrue(app.buttons["������� ����� ����"].waitForExistence(timeout:4))
        app.buttons["������� ����� ����"].tap()
        XCTAssertTrue(app.alerts["������� ����� ����"].waitForExistence(timeout:4))
        capture("02-auto-confirmation-simulator-fixture")
        app.alerts.buttons["������� ����"].tap()
        XCTAssertTrue(app.staticTexts["���� � 13 ��������"].waitForExistence(timeout:6))
        capture("03-auto-profile-simulator-fixture")
    }

    func testSharedZipImportsThirteenWithoutDuplicateError() {
        let app=XCUIApplication()
        app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU","--vpn013-test-import"]
        app.launch()
        XCTAssertTrue(app.staticTexts["������"].waitForExistence(timeout:20))
        XCTAssertEqual(app.alerts.count,0)
        for name in ["��������","��������","�������� 2","������","�������","����������","������","������ 2","���","������","���������","��������� 2","������"] {
            XCTAssertEqual(app.tables.cells.staticTexts.matching(identifier:name).count,1)
        }
        capture("04-shared-zip-26-files-13-imported")
        app.buttons["vpn013.add-profile"].tap()
        app.buttons["������� ����� ����"].tap()
        XCTAssertTrue(app.alerts["������� ����� ����"].waitForExistence(timeout:5))
        app.alerts.buttons["������� ����"].tap()
        XCTAssertTrue(app.staticTexts["���� � 13 ��������"].waitForExistence(timeout:6))
    }

    private func createFromPersonalServers(count: Int, label: String) {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", String(count)]
        app.launch()
        XCTAssertTrue(app.staticTexts["������ ������ 1"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        let action = app.buttons["������� ����� ����"]
        XCTAssertTrue(action.waitForExistence(timeout:5)); XCTAssertTrue(action.isEnabled)
        action.tap()
        let confirmation = app.alerts["������� ����� ����"]
        XCTAssertTrue(confirmation.waitForExistence(timeout:5))
        XCTAssertTrue(confirmation.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "� ������ ����: " + label)).firstMatch.exists)
        capture("dynamic-\(count)-personal-servers-confirmation")
        confirmation.buttons["������� ����"].tap()
        XCTAssertTrue(app.navigationBars["���� � " + label].waitForExistence(timeout:6))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format:"label CONTAINS %@", "� ������ ����: " + label)).firstMatch.exists)
        capture("dynamic-\(count)-personal-servers-saved")
    }

    func testFivePersonalServers() { createFromPersonalServers(count:5, label:"5 ��������") }
    func testTwoPersonalServers() { createFromPersonalServers(count:2, label:"2 �������") }
    func testSinglePersonalServerExplainsNoReserve() { createFromPersonalServers(count:1, label:"1 ������") }
    func testMoreThanThirteenPersonalServers() { createFromPersonalServers(count:26, label:"26 ��������") }
    func testThirtyPersonalServers() { createFromPersonalServers(count:30, label:"30 ��������") }
    func testFourteenPersonalServers() { createFromPersonalServers(count:14, label:"14 ��������") }
    func testEmptyListDisablesAutomaticCreation() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "0"]
        app.launch()
        XCTAssertTrue(app.buttons["vpn013.add-profile"].waitForExistence(timeout:20))
        app.buttons["vpn013.add-profile"].tap()
        XCTAssertTrue(app.buttons["������ ������������"].isEnabled)
        XCTAssertTrue(app.buttons["1 ��� ���������"].isEnabled)
        let action = app.buttons["������� ����� ����"]
        XCTAssertTrue(action.waitForExistence(timeout:5)); XCTAssertFalse(action.isEnabled)
        capture("dynamic-0-creation-disabled")
    }

    func testCenteredAddShowsPurchaseAndFreeHour() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "0"]
        app.launch()
        let add = app.buttons.matching(identifier: "addEmptyStateButton").firstMatch
        XCTAssertTrue(add.waitForExistence(timeout:20))
        add.tap()
        XCTAssertTrue(app.buttons["������ ������������"].waitForExistence(timeout:5))
        XCTAssertTrue(app.buttons["������ ������������"].isEnabled)
        XCTAssertTrue(app.buttons["1 ��� ���������"].isEnabled)
        capture("empty-list-centered-add-purchase-menu")
    }

    func testRedesignedListKeepsNativeControls() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2"]
        app.launch()
        XCTAssertTrue(app.navigationBars["VPN013 WG"].waitForExistence(timeout:20))
        let profile = app.tables.cells.containing(.staticText, identifier:"������ ������ 1").firstMatch
        XCTAssertTrue(profile.waitForExistence(timeout:5))
        let toggle = profile.switches.firstMatch
        XCTAssertTrue(toggle.exists)
        XCTAssertTrue(toggle.isEnabled)
        XCTAssertTrue(toggle.isHittable)
        XCTAssertLessThanOrEqual(toggle.frame.width, 80, "The native switch must not stretch across the row")
        let latency = profile.staticTexts["vpn013.latency"]
        XCTAssertTrue(latency.exists)
        XCTAssertLessThan(latency.frame.maxX, toggle.frame.minX)
        XCTAssertTrue(app.buttons["���������"].isHittable)
        XCTAssertTrue(app.buttons["vpn013.add-profile"].isHittable)
        capture("07-dark-native-list-two-personal-servers")
        profile.staticTexts["������ ������ 1"].tap()
        XCTAssertTrue(app.navigationBars["������ ������ 1"].waitForExistence(timeout:5))
        capture("08-dark-list-opens-profile-detail")
    }

    func testAddMenuKeepsAllActions() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", "2"]
        app.launch()
        let add = app.buttons["vpn013.add-profile"]
        XCTAssertTrue(add.waitForExistence(timeout:20))
        add.tap()
        XCTAssertTrue(app.buttons["������ ������������"].waitForExistence(timeout:5))
        for title in ["������ ������������", "1 ��� ���������", "������� �� ����� ��� ������", "������� ����� ����", "������� �� QR-����", "������� � ����"] {
            let action = app.buttons[title]
            XCTAssertTrue(action.exists, "Missing add-menu action: " + title)
            XCTAssertTrue(action.isEnabled, "Disabled add-menu action: " + title)
        }
        capture("09-dark-list-complete-add-menu")
        app.buttons["������� � ����"].tap()
        XCTAssertTrue(app.navigationBars["����� ������������"].waitForExistence(timeout:5))
        capture("09b-native-new-config-form")
        app.navigationBars["����� ������������"].buttons["��������"].tap()
        XCTAssertTrue(app.navigationBars["VPN013 WG"].waitForExistence(timeout:5))
    }

    func testDeveloperFooterAvailable() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "-AppleInterfaceStyle", "Dark"]
        app.launch()
        XCTAssertTrue(app.tables.cells.staticTexts["��������"].waitForExistence(timeout:20))
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
        XCTAssertTrue(app.staticTexts["����������� VPN013 WG"].exists)
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
        XCTAssertTrue(app.staticTexts["����������� VPN013 WG"].exists)
        XCTAssertTrue(add.isHittable)
        capture("12-dark-empty-list-developer-footer-simulator-fixture")
    }

    func testLargeTextKeepsSwitchAndDeveloperFooter() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU",
                               "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
                               "--vpn013-test-count", "2"]
        app.launch()
        let first = app.tables.cells.containing(.staticText, identifier:"������ ������ 1").firstMatch
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
        XCTAssertTrue(app.buttons["���������"].waitForExistence(timeout:20))
        app.buttons["���������"].tap()
        app.buttons["vpn013.view-log"].tap()
        let logText = app.textViews.matching(identifier:"vpn013.log-content").firstMatch
        XCTAssertTrue(logText.waitForExistence(timeout:5))
        XCTAssertTrue((logText.value as? String ?? "").contains("������ ����������"))
        XCTAssertFalse(app.activityIndicators["vpn013.log-loading"].isHittable)
        capture("06-log-unavailable-no-infinite-spinner-simulated")
    }
}
