/* test_cap_ls_multiline.c -- `CAP LS *` continuation chunking (#729).
 *
 * cap-3.2 S3.1.2: a capability list that does not fit one 512-byte line is
 * split across `CAP * LS * :<chunk>` lines with a final `CAP * LS :<chunk>`,
 * cut on capability boundaries. This walks a synthetic >512-byte list
 * through cap_ls_chunk() -- the splitter the sender uses -- and asserts the
 * chunks cover the list whole, never split a name, and stay within budget,
 * plus the short-list case: one chunk, byte-identical to the input. */
#include <stdio.h>
#include <string.h>

#include "core/cap.h"

static int g_failures = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            char msg_[512];                                                   \
            (void)snprintf(msg_, sizeof msg_, __VA_ARGS__);                   \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, msg_);             \
            g_failures++;                                                     \
            return;                                                           \
        }                                                                     \
    } while (0)

/* A >512-byte list of distinct fixed-width tokens, so every chunk boundary
 * is checkable by value rather than by length alone. */
static void build_long_list(char *out, size_t cap)
{
    size_t off = 0u;

    for (int i = 0; i < 60; i++) {
        int n = snprintf(out + off, cap - off, "%svery-long-capability-%02d",
                         (off != 0u) ? " " : "", i);
        if (n <= 0 || (size_t)n >= cap - off) {
            break;
        }
        off += (size_t)n;
    }
}

static void test_long_list_chunks(void)
{
    char list[1024];
    /* A representative per-line payload budget: 512 minus framing. */
    const size_t budget = 400u;
    size_t off = 0u;
    size_t chunks = 0u;
    char rejoined[1024];
    size_t rlen = 0u;

    build_long_list(list, sizeof list);
    CHECK(strlen(list) > 512u, "synthetic list is %zu bytes, not over 512",
          strlen(list));

    while (off < strlen(list)) {
        size_t n = cap_ls_chunk(list, off, budget);

        CHECK(n > 0u, "chunk %zu is empty at offset %zu", chunks, off);
        CHECK(n <= budget, "chunk %zu is %zu bytes, over the %zu budget",
              chunks, n, budget);
        /* Cut on a boundary: the chunk ends at the string or before a space,
         * and never mid-name. */
        CHECK(list[off + n] == '\0' || list[off + n] == ' ',
              "chunk %zu splits a capability name", chunks);
        CHECK(rlen + n + 1u < sizeof rejoined, "rejoin overflow");
        if (chunks != 0u) {
            rejoined[rlen++] = ' ';
        }
        memcpy(rejoined + rlen, list + off, n);
        rlen += n;
        off += n;
        if (list[off] == ' ') {
            off++;
        }
        chunks++;
    }
    rejoined[rlen] = '\0';
    CHECK(chunks > 1u, "a >512-byte list produced one chunk");
    CHECK(strcmp(rejoined, list) == 0, "chunks do not rejoin to the list");
    printf("PASS long list: %zu bytes in %zu chunks\n", strlen(list), chunks);
}

static void test_short_list_single_chunk(void)
{
    const char *list = "multi-prefix message-tags sasl extended-join";
    size_t n = cap_ls_chunk(list, 0u, 400u);

    CHECK(n == strlen(list), "short list chunked: got %zu of %zu", n,
          strlen(list));
    CHECK(cap_ls_chunk(list, strlen(list), 400u) == 0u,
          "no terminator chunk past the end");
}

static void test_empty_and_null(void)
{
    CHECK(cap_ls_chunk("", 0u, 400u) == 0u, "empty list yields a chunk");
    CHECK(cap_ls_chunk(NULL, 0u, 400u) == 0u, "NULL list yields a chunk");
    CHECK(cap_ls_chunk("a b", 0u, 0u) == 0u, "zero budget yields a chunk");
    CHECK(cap_ls_chunk("a b", 99u, 400u) == 0u,
          "past-the-end offset yields a chunk");
}

static void test_oversize_token_whole(void)
{
    /* One name longer than the budget cannot be split; it is returned whole
     * rather than dropped, so the sender emits it rather than hiding it. */
    char tok[100];
    char list[160];
    size_t n;

    memset(tok, 'x', sizeof tok - 1u);
    tok[sizeof tok - 1u] = '\0';
    snprintf(list, sizeof list, "ab %s cd", tok);
    n = cap_ls_chunk(list, 0u, 10u);
    CHECK(n == 2u, "first chunk is %zu, want 2", n);
    n = cap_ls_chunk(list, 3u, 10u);
    CHECK(n == strlen(tok), "oversize token split: got %zu of %zu", n,
          strlen(tok));
}

int main(void)
{
    test_long_list_chunks();
    test_short_list_single_chunk();
    test_empty_and_null();
    test_oversize_token_whole();
    if (g_failures != 0) {
        printf("FAILURES: %d\n", g_failures);
        return 1;
    }
    printf("OK cap-ls-multiline\n");
    return 0;
}
