/* test_short_secret.c -- issue #205: short secrets are refused.
 *
 * A unit test -- no sockets, no children, no loop -- because the claim is
 * about fed_open()'s configuration gate: a non-empty secret below
 * IRC_FED_MIN_SECRET is refused (-1, node left unopened) unless the
 * IRC_SERVE_ALLOW_SHORT_SECRET escape hatch is set, while "" (opt-out of
 * federation) and a 16-byte secret still open.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/server.h"
#include "federation/link.h"

int main(void)
{
    server_t s;

    /* --- short is refused, node left unopened --------------------------- */
    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "tiny") != 0);
    assert(s.fed_opened == 0);
    server_shutdown(&s);

    /* --- empty still means "federates with nobody", not an error --------- */
    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "") == 0);
    fed_close(&s);
    server_shutdown(&s);

    /* --- exactly the floor opens ----------------------------------------- */
    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "0123456789abcdef") == 0);
    assert(strcmp(s.fed_secret, "0123456789abcdef") == 0);
    fed_close(&s);
    server_shutdown(&s);

    /* --- the escape hatch keeps legacy test secrets working ------------- */
    assert(server_init(&s, "irc.a") == 0);
    assert(setenv("IRC_SERVE_ALLOW_SHORT_SECRET", "1", 1) == 0);
    assert(fed_open(&s, "tiny") == 0);
    assert(strcmp(s.fed_secret, "tiny") == 0);
    fed_close(&s);
    assert(unsetenv("IRC_SERVE_ALLOW_SHORT_SECRET") == 0);
    server_shutdown(&s);

    return 0;
}
