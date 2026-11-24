/* handshake.c -- the federation handshake FSM, split out of federation/link.c
 * (issue #543). Everything here operates on a caller-owned handshake_ctx_t
 * and nothing else. */
#include "federation_handshake.h"

#include <stddef.h>

void handshake_init(handshake_ctx_t *ctx) {
    if (ctx == NULL) return;
    ctx->state = INIT;
}

handshake_state_t handshake_state(const handshake_ctx_t *ctx) {
    if (ctx == NULL) return INIT;
    return ctx->state;
}

/* All transition functions share the same reject pattern: return -1 and do
 * not modify the context when the precondition is unmet or the context is
 * NULL. A rejected transition is therefore observable via the return value
 * and leaves the state unchanged. */

int handshake_send(handshake_ctx_t *ctx) {
    if (ctx == NULL) return -1;
    if (ctx->state != INIT) return -1;
    ctx->state = HANDSHAKE_SENT;
    return 0;
}

int handshake_receive(handshake_ctx_t *ctx) {
    if (ctx == NULL) return -1;
    if (ctx->state != HANDSHAKE_SENT) return -1;
    ctx->state = ESTABLISHED;
    return 0;
}

int handshake_fail(handshake_ctx_t *ctx) {
    if (ctx == NULL) return -1;
    if (ctx->state != HANDSHAKE_SENT && ctx->state != ESTABLISHED) return -1;
    ctx->state = FAILED;
    return 0;
}

int handshake_timeout(handshake_ctx_t *ctx) {
    if (ctx == NULL) return -1;
    if (ctx->state != HANDSHAKE_SENT) return -1;
    ctx->state = TIMED_OUT;
    return 0;
}

void handshake_reset(handshake_ctx_t *ctx) {
    if (ctx == NULL) return;
    ctx->state = INIT;
}

int heartbeat_check(const handshake_ctx_t *ctx) {
    if (ctx == NULL) return 1; /* not linked */
    return (ctx->state == ESTABLISHED) ? 0 : 1;
}
