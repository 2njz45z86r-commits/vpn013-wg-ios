// SPDX-License-Identifier: MIT
import Foundation

/// Decimal network rates (bits/s), separate from transferred amounts (bytes).
enum VPN013TrafficDisplay {
    static func amount(_ bytes: UInt64?) -> String {
        guard let bytes = bytes else { return "—" }
        return compact(Double(bytes), units: ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ", "ЭБ"])
    }
    static func speed(_ bytesPerSecond: Double?) -> String {
        guard let value = bytesPerSecond else { return "—" }
        return compact(value * 8, units: ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с", "Тбит/с", "Пбит/с", "Эбит/с", "Збит/с", "Ибит/с"])
    }
    private static func compact(_ input: Double, units: [String]) -> String {
        guard input.isFinite, input >= 0 else { return "—" }
        var value = input, index = 0
        while value >= 1000, index + 1 < units.count { value /= 1000; index += 1 }
        value = (value * 10).rounded(.toNearestOrAwayFromZero) / 10
        if value >= 1000, index + 1 < units.count { value /= 1000; index += 1 }
        var number = String(format: "%.1f", locale: Locale(identifier: "en_US_POSIX"), value)
        if number.hasSuffix(".0") { number.removeLast(2) }
        return number.replacingOccurrences(of: ".", with: ",") + " " + units[index]
    }
}

/// UI-only measurement: never infers rate from the lifetime byte count.
struct VPN013TrafficSampler {
    struct Rate: Equatable { let received: Double; let sent: Double }
    private struct Sample { let identity: String; let time: Double; let received: UInt64; let sent: UInt64 }
    private var previous: Sample?
    private var latest: Rate?
    mutating func reset() { previous = nil; latest = nil }
    mutating func sample(identity: String, time: Double, received: UInt64?, sent: UInt64?) -> Rate? {
        guard !identity.isEmpty, time.isFinite, time >= 0, let received = received, let sent = sent else { reset(); return nil }
        let current = Sample(identity: identity, time: time, received: received, sent: sent)
        guard let old = previous, old.identity == identity, received >= old.received, sent >= old.sent,
              time > old.time, time - old.time <= 30 else { previous = current; latest = nil; return nil }
        let elapsed = time - old.time
        if elapsed < 0.25 { return latest }
        previous = current
        latest = Rate(received: Double(received - old.received) / elapsed, sent: Double(sent - old.sent) / elapsed)
        return latest
    }
}
