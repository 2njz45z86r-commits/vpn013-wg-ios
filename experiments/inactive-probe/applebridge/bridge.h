// SPDX-License-Identifier: MIT
#ifndef R013_EXPERIMENTAL_UDP_BRIDGE_H
#define R013_EXPERIMENTAL_UDP_BRIDGE_H
#include <stdint.h>
#include <stddef.h>

// Only integer handles cross the boundary, never a retained Go/Swift pointer.
// A nonzero open result guarantees no platform session was created.
typedef int32_t (*r013_udp_open_fn)(uint64_t owner, uint64_t session,
                                   const char *host, uint16_t port);
// Copy packet bytes before returning. Completion is a separate callback.
typedef void (*r013_udp_write_fn)(uint64_t owner, uint64_t session,
                                  const void *packet, uint32_t length, uint64_t write_id);
// Must eventually call DidClose AFTER actual socket cancellation/quiescence.
typedef void (*r013_udp_cancel_fn)(uint64_t owner, uint64_t session);
typedef void (*r013_udp_quiesced_fn)(uint64_t owner);

typedef struct {
    uint64_t owner;
    uint32_t route; // 1=physical candidate; 2=current virtual tunnel. No default.
    r013_udp_open_fn open;
    r013_udp_write_fn write;
    r013_udp_cancel_fn cancel;
    r013_udp_quiesced_fn quiesced;
} r013_udp_driver;

uint64_t R013RegisterUDPDriver(r013_udp_driver callbacks);
int32_t R013UnregisterUDPDriver(uint64_t driver);
void R013UDPDeliver(uint64_t session, void *packet, uint32_t length);
void R013UDPWriteDone(uint64_t session, uint64_t write_id, int32_t failed);
void R013UDPFailed(uint64_t session);
void R013UDPDidClose(uint64_t session);

// Thread-safe production controller ABI. Begin/Cancel/Release MAY BLOCK while
// waiting for actual UDP close (at most10s); invoke off the main/UDP queues.
// A zero transition is a FAILURE, never permission to change the primary VPN.
// Only integer handles and bounded, synchronously-copied bytes cross this ABI.
uint64_t R013ProbeCreate(uint64_t physical_driver, uint64_t current_driver);
uint64_t R013ProbeBeginChange(uint64_t controller);
// known=0: unknown; known=1,length=0: idle; known=1,config: actual active UAPI.
// Invalid active configuration leaves membership UNKNOWN and returns nonzero.
int32_t R013ProbeCommitChange(uint64_t controller, uint64_t transition, int32_t known, void *config, uint32_t length);
uint64_t R013ProbeStartScan(uint64_t controller, void *json, uint32_t length);
// Returns exact JSON length, or -1. Output has no NUL, key or configuration.
int32_t R013ProbePollScan(uint64_t controller, uint64_t operation, void *out, uint32_t capacity);
int32_t R013ProbeCancelScan(uint64_t controller, uint64_t operation);
// JSON contains exactly one FRESH selected snapshot and the SAME resolver.
uint64_t R013ProbeBeginChoice(uint64_t controller, uint64_t operation, void *json, uint32_t length);
int32_t R013ProbeRelease(uint64_t controller);
#ifdef R013_BRIDGE_TESTING
int32_t R013BridgeExercise(uint64_t driver);
int32_t R013BridgeDNSExercise(uint64_t driver);
#endif

static inline int32_t r013_call_open(r013_udp_driver cb, uint64_t session, const char *host, uint16_t port) {
    return cb.open(cb.owner, session, host, port);
}
static inline void r013_call_write(r013_udp_driver cb, uint64_t session, const void *packet, uint32_t length, uint64_t write_id) {
    cb.write(cb.owner, session, packet, length, write_id);
}
static inline void r013_call_cancel(r013_udp_driver cb, uint64_t session) {
    cb.cancel(cb.owner, session);
}
static inline void r013_call_quiesced(r013_udp_driver cb) {
    if (cb.quiesced) cb.quiesced(cb.owner);
}
static inline void r013_deliver_buffer(uint64_t session, const void *packet, uint32_t length) {
    R013UDPDeliver(session, (void *)packet, length);
}
#endif
