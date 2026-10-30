import Foundation

@main enum TrafficDisplayTests {
    static func main() {
        var count = 0
        func check(_ condition: Bool) { count += 1; precondition(condition, "traffic case \(count)") }
        let rates: [(Double, String)] = [
            (0,"0 бит/с"),(1,"8 бит/с"),(125,"1 Кбит/с"),(1250,"10 Кбит/с"),
            (125000,"1 Мбит/с"),(250000,"2 Мбит/с"),(2500000,"20 Мбит/с"),
            (125000000,"1 Гбит/с"),(125000000000,"1 Тбит/с"),
            (124987.5,"999,9 Кбит/с"),(124993.75,"1 Мбит/с"),(.nan,"—"),(.infinity,"—"),(-1,"—")]
        for (value, expected) in rates { check(VPN013TrafficDisplay.speed(value) == expected) }
        let volumes: [(UInt64, String)] = [(0,"0 Б"),(999,"999 Б"),(1000,"1 КБ"),(1500,"1,5 КБ"),
            (999950,"1 МБ"),(1000000,"1 МБ"),(2500000,"2,5 МБ"),(1000000000,"1 ГБ"),(UInt64.max,"18,4 ЭБ")]
        for (value, expected) in volumes { check(VPN013TrafficDisplay.amount(value) == expected) }
        check(VPN013TrafficDisplay.amount(nil) == "—")
        var sampler = VPN013TrafficSampler()
        check(sampler.sample(identity: "a", time: 0, received: 0, sent: 0) == nil)
        let rate = sampler.sample(identity: "a", time: 2, received: 500000, sent: 125000)
        check(VPN013TrafficDisplay.speed(rate?.received) == "2 Мбит/с" && VPN013TrafficDisplay.speed(rate?.sent) == "500 Кбит/с")
        check(sampler.sample(identity: "a", time: 2.1, received: 510000, sent: 126000) == rate)
        check(VPN013TrafficDisplay.speed(sampler.sample(identity: "a", time: 4, received: 500000, sent: 125000)?.received) == "0 бит/с")
        check(sampler.sample(identity: "a", time: 6, received: 1000, sent: 1000) == nil)
        check(sampler.sample(identity: "b", time: 8, received: 5000000, sent: 5000000) == nil)
        check(sampler.sample(identity: "b", time: 40, received: 6000000, sent: 6000000) == nil)
        check(sampler.sample(identity: "b", time: 41, received: nil, sent: nil) == nil)
        check(sampler.sample(identity: "b", time: 42, received: 6000000, sent: 6000000) == nil)
        check(sampler.sample(identity: "b", time: 41, received: 7000000, sent: 7000000) == nil)
        print("TrafficDisplayTests: \(count) checks passed")
    }
}
