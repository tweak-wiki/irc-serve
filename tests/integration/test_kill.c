/* test_kill.c -- KILL on the wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 4.2 and RFC 2812 3.7.1 (KILL is gated on an IRC
 * operator), 4.4 (481 ERR_NOPRIVILEGES). See commands_choper.c's handle_kill()
 * for the refusal. This node has no operator model, so every KILL from a
 * client is 481 -- issue #670, where KILL answered 421 because the dispatch
 * table held it with a NULL handler.
 *
 * The property under test is the refusal, and -- as in test_knock.c -- a
 * refusal that is only checked positively is a stub that passes. So each
 * input asserts the RIGHT numeric came back AND that the others did not:
 *
 *   451  the client has not registered. KILL is in the command table with
 *        pre_reg == 0, so the registration gate answers before handle_kill()
 *        is reached.
 *   481  everything else. 421 must never appear: KILL is recognised (3.7.1
 *        names it), so 421 would claim this server predates the verb.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect(), and every negative assertion is scoped to a window closed by a
 * PING drain.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

#define BIN_NAME "irc.test"

static size_t g_opened;

static void client_register(test_client_t *c, nf_node_t *node, const char *nick)
{
    char line[512];

    tc_init(c);
    g_opened++;
    TF_CHECK_MSG(tc_connect(c, node->port) == 0, "tc_connect(%s) failed", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s did not register",
                 nick);
    TF_CHECK_MSG(tc_send(c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

static unsigned g_drain_seq;

static size_t mark(test_client_t *c)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :m%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s m%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(c, line) == 0, "mark PING send failed");
    TF_CHECK_MSG(tc_expect(c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(c), needle);
    TF_CHECK_MSG(at != NULL, "the mark PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(c)) : 0u;
}

static void expect_in_window(test_client_t *c, size_t from, size_t end,
                             const char *what, const char *want)
{
    const char *base = tc_buffer(c);
    const char *at;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu)", what, from,
                 end);
    at = strstr(base + from, want);
    TF_CHECK_MSG(at != NULL, "%s: expected the exact line \"%s\"", what, want);
    if (at == NULL) {
        return;
    }
    TF_CHECK_MSG(at < base + end,
                 "%s: \"%s\" appears only AFTER the window closed, so it was not "
                 "an answer to the command under test",
                 what, want);
    TF_CHECK_MSG(at == base + from || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one",
                 what, want);
}

static void expect_absent_in_window(test_client_t *c, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did "
                 "not appear\" would prove nothing",
                 what, from, end);
    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        count++;
        p = hit + strlen(needle);
    }
    TF_CHECK_MSG(count == 0,
                 "%s: \"%s\" appeared %zu time(s) in the window and must not have "
                 "appeared at all",
                 what, needle, count);
}

int main(void)
{
    nf_node_t node;
    test_client_t alice, raw;
    size_t from, end;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_register(&alice, &node, "alice");

    /* A registered client's KILL is 481, carrying no target: the refusal is
     * about the caller's privileges, and there is nothing to look up. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice, "KILL somebody :die") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "481 for a registered KILL",
                     ":" BIN_NAME " 481 alice :You're not an IRC operator\r\n");
    /* 421 is the #670 regression: KILL once answered "Unknown command". 462
     * and 464 are the neighbouring refusals a confused handler could emit. */
    expect_absent_in_window(&alice, from, end, "the registered KILL", " 421 ");
    expect_absent_in_window(&alice, from, end, "the registered KILL", " 462 ");
    expect_absent_in_window(&alice, from, end, "the registered KILL", " 464 ");

    /* The node records the refusal rather than the verb as unimplemented. */
    TF_CHECK_MSG(nf_expect(&node, "kill_refused: by=alice", T_IO_MS) == 0,
                 "the node did not record the KILL refusal");

    /* The registration gate answers before the handler does: NICK without
     * USER is not a user of this network, so 451, not 481. */
    tc_init(&raw);
    g_opened++;
    TF_CHECK_MSG(tc_connect(&raw, node.port) == 0, "tc_connect(raw) failed");
    TF_CHECK_MSG(tc_send(&raw, "NICK early") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&raw, "KILL somebody :die") == 0, "KILL send failed");
    TF_CHECK_MSG(tc_expect(&raw, " 451 ", T_IO_MS) == 0,
                 "an unregistered client was not answered with 451");
    TF_CHECK_MSG(strstr(tc_buffer(&raw), " 481 ") == NULL,
                 "an unregistered client's KILL reached the handler and was "
                 "answered 481 instead of being stopped by the registration gate");
    /* And it registers and is refused normally afterwards, so the gate is a
     * gate and not a state the connection is stuck in. */
    TF_CHECK_MSG(tc_send(&raw, "USER early 0 * :Real early") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&raw, " 001 ", T_IO_MS) == 0, "raw did not register");
    TF_CHECK_MSG(tc_send(&raw, "KILL somebody :die") == 0, "KILL send failed");
    TF_CHECK_MSG(tc_expect(&raw, ":" BIN_NAME " 481 early ", T_IO_MS) == 0,
                 "a registered client was not answered with 481, so the "
                 "registration gate is not what stopped the earlier KILL");

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice);
    tc_close(&raw);
    nf_free(&node);
    tf_done("kill");
    return 0;
}
