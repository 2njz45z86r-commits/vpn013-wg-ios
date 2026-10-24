import Foundation
var checks = 0
func check(_ value: @autoclosure () -> Bool, _ label: String) {
    precondition(value(), label); checks += 1
}
for count in 1...40 {
for start in 0..<count {
    var policy=AutoFailoverPolicy(count:count,initialIndex:start)
    var seen:Set<Int>=[start]
    check(policy.record(healthy:true,networkAvailable:true) == .stay,"healthy stays")
    for _ in 0..<(count - 1) {
        check(policy.record(healthy:false,networkAvailable:true) == .wait(5),"single failed probe is insufficient")
        guard case .switchTo(let next)=policy.record(healthy:false,networkAvailable:true) else { fatalError("missing fallback") }
        check(seen.insert(next).inserted,"no repeats within pass")
    }
    check(seen.count==count,"every candidate visited")
    _=policy.record(healthy:false,networkAvailable:true)
    check(policy.record(healthy:false,networkAvailable:true) == .wait(60),"all failed backs off")
    let current=policy.current
    for _ in 0..<100 { check(policy.record(healthy:false,networkAvailable:false) == .wait(15),"offline never rotates") }
    check(policy.current==current,"offline keeps candidate")
    check(policy.record(healthy:true,networkAvailable:true) == .stay,"recovery stops rotation")
    policy.stop()
    for _ in 0..<10 { check(policy.record(healthy:false,networkAvailable:true) == .stopped,"manual stop persists") }
}
}
print("AutoFailoverPolicy: \(checks) assertions passed; counts 1...40, every initial server, recovery, offline, exhaustion, stop")

for count in 1...30 {
    var policy=AutoFailoverPolicy(count:count)
    check(policy.record(healthy:true,networkAvailable:true,latencyMilliseconds:1200) == .stay,"1200ms is allowed")
    let decision=policy.record(healthy:true,networkAvailable:true,latencyMilliseconds:1201)
    check(decision == (count == 1 ? .wait(60) : .switchTo(1)),"over 1200ms rotates immediately with bounded exhaustion")
    check(policy.record(healthy:true,networkAvailable:false,latencyMilliseconds:5000) == .wait(15),"offline never rotates due to latency")
    check(policy.record(healthy:true,networkAvailable:true,latencyMilliseconds:100) == .stay,"latency recovery resets pass")
    check(policy.record(healthy:false,networkAvailable:true) == .wait(5),"one failure waits for actual second attempt")
    check(policy.record(healthy:true,networkAvailable:true,latencyMilliseconds:100) == .stay,"success clears previous failure")
    check(policy.record(healthy:false,networkAvailable:true) == .wait(5),"success prevents stale failure counting")
    policy.stop()
    check(policy.record(healthy:true,networkAvailable:true,latencyMilliseconds:5000) == .stopped,"latency cannot restart a stopped tunnel")
}
print("AutoFailoverPolicy latency checks passed: 1200ms boundary, slow fallback, recovery, actual failure counting, offline and manual stop; total \(checks)")

for count in 1...30 {
    var policy = AutoFailoverPolicy(count: count)
    _ = policy.record(healthy: false, networkAvailable: true)
    policy.selectMeasuredCandidate(count - 1)
    check(policy.current == count - 1 && policy.failures == 0, "measured selection updates actual policy index")
    check(policy.record(healthy: false, networkAvailable: true) == .wait(5), "measured selection retains two-attempt rule")
    policy.selectMeasuredCandidate(count)
    check(policy.current == count - 1, "out-of-range measurement ignored")
    policy.stop(); policy.selectMeasuredCandidate(0)
    check(!policy.running && policy.current == count - 1, "measured choice cannot restart manual stop")
}
print("Measured selection policy: index consistency, fresh failure count and manual stop passed")
