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

typedef struct {
    uint64_t owner;
    r013_udp_open_fn open;
    r013_udp_write_fn write;
    r013_udp_cancel_fn cancel;
} r013_udp_driver;

uint64_t R013RegisterUDPDriver(r013_udp_driver callbacks);
int32_t R013UnregisterUDPDriver(uint64_t driver);
void R013UDPDeliver(uint64_t session, void *packet, uint32_t length);
void R013UDPWriteDone(uint64_t session, uint64_t write_id, int32_t failed);
void R013UDPFailed(uint64_t session);
void R013UDPDidClose(uint64_t session);
#ifdef R013_BRIDGE_TESTING
int32_t R013BridgeExercise(uint64_t driver);
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
static inline void r013_deliver_buffer(uint64_t session, const void *packet, uint32_t length) {
    R013UDPDeliver(session, (void *)packet, length);
}
#endif
