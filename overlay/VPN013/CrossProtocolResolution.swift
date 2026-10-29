// SPDX-License-Identifier: MIT
import Foundation

/// Resolve the imported endpoints before installing tunnel routes. Six workers
/// and an eight-second collection window; a dead first VPN must not own DNS for
/// the reserves. Late DNS results never restart a stopped session.
final class CrossProtocolResolution {
    private let queue = OperationQueue()
    private let lock = NSLock()
    private var results: [String: String] = [:]
    private var ended = false
    private var deadline: DispatchWorkItem?
    private var completion: (([String: String]) -> Void)?
    func start(_ plan: CrossProtocolPlan, completion: @escaping ([String: String]) -> Void) throws {
        dispatchPrecondition(condition: .onQueue(.main))
        try plan.validate(); self.completion = completion
        var lists: [[(String, UInt16)]] = []
        for group in plan.groups {
            if let awg = group.awg {
                lists.append(try awg.validatedConfigurations().flatMap { configuration -> [(String, UInt16)] in
                    configuration.peers.compactMap { peer -> (String, UInt16)? in
                        guard let endpoint = peer.endpoint, let port = UInt16(endpoint.stringRepresentation.split(separator: ":").last ?? "") else { return nil }
                        return (String(describing: endpoint.host), port)
                    }
                })
            } else if let proxy = group.proxy {
                lists.append(proxy.candidates.flatMap { profile in [(profile.host, profile.port)] + profile.additionalEndpoints.map { ($0.host, $0.port) } })
            }
        }
        var hosts: [(String, UInt16)] = [], seen = Set<String>()
        for index in 0..<(lists.map { $0.count }.max() ?? 0) {
            for list in lists where list.indices.contains(index) {
                if seen.insert(list[index].0).inserted { hosts.append(list[index]) }
            }
        }
        guard hosts.count <= 1024 else { throw CrossProtocolError.tooMany }
        queue.maxConcurrentOperationCount = 6; queue.qualityOfService = .userInitiated
        let group = DispatchGroup()
        for (host, port) in hosts {
            group.enter()
            let operation = BlockOperation { [weak self] in
                guard let address = ProxySinglePacketAdapter.resolve(host, port: port), let self = self else { return }
                self.lock.lock(); defer { self.lock.unlock() }
                if !self.ended { self.results[host] = address }
            }
            operation.completionBlock = { group.leave() }; queue.addOperation(operation)
        }
        group.notify(queue: .main) { [weak self] in self?.finish() }
        let deadline = DispatchWorkItem { [weak self] in self?.finish() }; self.deadline = deadline
        DispatchQueue.main.asyncAfter(deadline: .now() + 8, execute: deadline)
    }
    private func finish() {
        dispatchPrecondition(condition: .onQueue(.main))
        lock.lock(); let already = ended; ended = true; let values = results; lock.unlock()
        guard !already else { return }
        deadline?.cancel(); deadline = nil; queue.cancelAllOperations()
        let done = completion; completion = nil; done?(values)
    }
    func cancel() {
        dispatchPrecondition(condition: .onQueue(.main))
        completion = nil; finish()
    }
}
