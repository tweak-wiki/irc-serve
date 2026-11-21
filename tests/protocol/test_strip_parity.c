/* test_strip_parity.c -- the relay-vs-stored strip split, pinned (#320).
 *
 * Stored fields strip every C0/C1 control; relay text keeps the eight mIRC
 * bytes (notably 0x01, the CTCP delimiter) and drops the rest, including ESC
 * and raw C1. Issue #285's merge must not reconverge the two policies, so one
 * input is run through both strippers and each side asserts its own answer.
 * Octal escapes throughout: "\x01hello" is safe but "\x1b..."-style runs are
 * exactly the greediness test_control_bytes.c documents avoiding. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "core/connection.h"

int main(void)
{
    /* "\033\001hello\200": ESC, CTCP delimiter, text, raw C1. */
    static const char input[] = "\033\001hello\200";
    char relay[32];
    char stored[32];
    size_t kept_relay;
    size_t kept_stored;

    kept_relay = conn_text_strip_relay(relay, sizeof relay, input);
    assert(kept_relay == strlen("\001hello"));
    assert(strcmp(relay, "\001hello") == 0);
    assert(strchr(relay, '\033') == NULL);
    assert(strchr(relay, '\200') == NULL);

    kept_stored = conn_text_strip(stored, sizeof stored, input);
    assert(kept_stored == strlen("hello"));
    assert(strcmp(stored, "hello") == 0);

    printf("ok: test_strip_parity\n");
    return 0;
}
