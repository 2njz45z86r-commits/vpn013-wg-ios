import XCTest
final class AutoTunnelUITests:XCTestCase {
    func capture(_ name:String) { let a=XCTAttachment(screenshot:XCUIScreen.main.screenshot());a.name=name;a.lifetime = .keepAlways;add(a) }
    func testCreateAutomaticFromThirteenImportedFixtures() {
        let app=XCUIApplication();app.launchArguments=["-AppleLanguages","(ru)","-AppleLocale","ru_RU"];app.launch()
        XCTAssertTrue(app.staticTexts["Беларусь"].waitForExistence(timeout:20))
        capture("01-thirteen-servers-simulator-fixture")
        app.navigationBars.buttons.element(boundBy:1).tap()
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
        for name in ["Беларусь","Германия","Германия 2","Грузия","Испания","Нидерланды","Польша","Польша 2","США","Турция","Финляндия","Финляндия 2","Швеция"] {
            XCTAssertEqual(app.staticTexts.matching(identifier:name).count,1)
        }
        capture("04-shared-zip-26-files-13-imported")
        app.navigationBars.buttons.element(boundBy:1).tap()
        app.buttons["Создать режим Авто"].tap()
        XCTAssertTrue(app.alerts["Создать режим Авто"].waitForExistence(timeout:5))
        app.alerts.buttons["Создать Авто"].tap()
        XCTAssertTrue(app.staticTexts["Авто · 13 серверов"].waitForExistence(timeout:6))
    }

    private func createFromPersonalServers(count: Int, label: String) {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU", "--vpn013-test-count", String(count)]
        app.launch()
        XCTAssertTrue(app.staticTexts["Личный сервер 1"].waitForExistence(timeout:20))
        app.navigationBars.buttons.element(boundBy:1).tap()
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
        XCTAssertTrue(app.navigationBars.buttons.element(boundBy:1).waitForExistence(timeout:20))
        app.navigationBars.buttons.element(boundBy:1).tap()
        XCTAssertTrue(app.buttons["Купить конфигурацию"].isEnabled)
        XCTAssertTrue(app.buttons["1 час бесплатно"].isEnabled)
        let action = app.buttons["Создать режим Авто"]
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
        XCTAssertTrue(app.buttons["Купить конфигурацию"].waitForExistence(timeout:5))
        XCTAssertTrue(app.buttons["Купить конфигурацию"].isEnabled)
        XCTAssertTrue(app.buttons["1 час бесплатно"].isEnabled)
        capture("empty-list-centered-add-purchase-menu")
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
}
