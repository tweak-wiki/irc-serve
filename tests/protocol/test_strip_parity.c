/* test_strip_parity.c -- the two strip policies agree on what they share (#285).
 *
 * One walk, one policy argument: STRIP_STORED drops every C0 control, STRIP_RELAY
 * keeps the eight mIRC bytes. The input holds one byte from each group -- ESC (a
 * hazard both drop), a raw 0x80 (C1, both drop), and 0x01 (CTCP, only RELAY
 * keeps) -- so the two outputs differ in exactly the policy byte.
 */
#include <assert.h>
#include <string.h>

#include "core/connection.h"

int main(void)
{
    static const char in[] = "\x1b\x80hello\x01";
    char relay[32];
    char stored[32];
    size_t n_relay;
    size_t n_stored;

    n_relay = conn_text_strip(relay, sizeof relay, in, STRIP_RELAY);
    n_stored = conn_text_strip(stored, sizeof stored, in, STRIP_STORED);

    /* RELAY keeps 0x01, drops ESC and the raw C1. */
    assert(n_relay == 6u);
    assert(memcmp(relay, "hello\x01", 6u) == 0);
    assert(relay[6] == '\0');

    /* STORED drops both. */
    assert(n_stored == 5u);
    assert(strcmp(stored, "hello") == 0);

    return 0;
}
