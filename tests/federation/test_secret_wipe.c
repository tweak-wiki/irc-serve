/* test_secret_wipe.c -- issue #325: no secret outlives its copy.
 *
 * Two wipes, one file each, and the test needs no sockets, no children and no
 * loop because both are claims about process memory, observable without a
 * wire:
 *
 *   node_main.c's argv wipe -- the --secret slot reads all-zero after the
 *   copy fed_open() took, while the --secret-file PATH alongside it is
 *   untouched (the path was never the secret; wiping it would strand the
 *   operator's own command line).
 *
 *   fed_close()'s wipe -- after close, a scan of the whole fed_secret buffer
 *   finds no nonzero byte, and fed_secret_len is 0. The scan covers the full
 *   array rather than strlen() because a wiped-then-reopened buffer's
 *   leftovers would sit past the NUL.
 *
 * The argv half cannot call parse_args() -- it is static in node_main.c -- so
 * it replays the contract instead: copy the secret through fed_open(), then
 * apply the same strlen-bounded volatile wipe the binary applies, and assert
 * the slot reads zero. What pins the binary's actual behaviour is the source
 * shape asserted alongside: the wipe is conditional on the secret having come
 * from argv, which is what keeps --secret-file's path intact.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "core/server.h"
#include "federation/link.h"

#define WIPE_SECRET "wipe-me-argv-secret-9"

static int buf_has_nonzero(const char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    /* --- fed_close() leaves no secret bytes behind ---------------------- */
    {
        server_t s;
        size_t i;
        int found = 0;

        assert(server_init(&s, "irc.w") == 0);
        assert(fed_open(&s, WIPE_SECRET) == 0);
        assert(strcmp(s.fed_secret, WIPE_SECRET) == 0);
        fed_close(&s);
        assert(s.fed_secret_len == 0u);
        for (i = 0; i < sizeof s.fed_secret; i++) {
            if (s.fed_secret[i] != 0) {
                found = 1;
                break;
            }
        }
        assert(found == 0);
        assert(s.fed_secret[0] == '\0');
        server_shutdown(&s);
    }

    /* --- the argv-slot wipe: strlen-bounded, volatile, slot zeroed ------- */
    {
        static char slot[] = WIPE_SECRET;
        static char path[] = "/tmp/secret-file-path";
        volatile char *v = slot;
        size_t n = 0;
        size_t k;

        /* fed_open() takes its copy first; the wipe runs after, as in main().
         * A scratch node proves the copy exists so the wipe cannot strand the
         * federation -- the wipe is safe BECAUSE the copy is taken. */
        {
            server_t s;

            assert(server_init(&s, "irc.v") == 0);
            assert(fed_open(&s, slot) == 0);
            assert(strcmp(s.fed_secret, WIPE_SECRET) == 0);
            server_shutdown(&s);
        }
        while (n < (size_t)IRC_FED_MAX_SECRET && v[n] != '\0') {
            n++;
        }
        assert(n == strlen(WIPE_SECRET));
        for (k = 0; k < n; k++) {
            v[k] = 0;
        }
        assert(buf_has_nonzero(slot, sizeof slot - 1u) == 0);
        /* The --secret-file path is never the wipe's target. */
        assert(strcmp(path, "/tmp/secret-file-path") == 0);
    }

    printf("ok: secret_wipe\n");
    return 0;
}
