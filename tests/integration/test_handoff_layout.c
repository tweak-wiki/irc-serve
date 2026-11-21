/* test_handoff_layout.c -- #368: the loop/writer handoff fields share their own
 * cache lines, apart from dispatch-only fields.
 *
 * The loop appends to the write queue while a writer drains it. If a handoff
 * field shared a line with dispatch-only data, every append would invalidate
 * the writer's line and vice versa -- the exact cost threading exists to
 * remove. So the struct ends with a handoff group (lock, readiness atoms,
 * queue head) that opens on a line boundary and fits in two lines, and this
 * test pins that: a field migrating across the boundary fails here.
 *
 * A _Static_assert would be the stronger check and is not available: clang's
 * -Weverything carries -Wpre-c11-compat, which objects to it, and this project
 * never narrows the warning set (see dedup.h). So the layout is a test
 * assertion, which means it has to be RUN -- and this is the one test that
 * includes connection.h for exactly that.
 */
#include <stddef.h>
#include <stdio.h>

#include "core/connection.h"

#define LINE(f) (offsetof(conn_t, f) / (size_t)CONN_CACHE_LINE)

static int fails = 0;

#define CHECK(cond, fmt, ...) do {                                          \
        if (!(cond)) {                                                      \
            ++fails;                                                        \
            (void)printf("handoff layout: " fmt "\n", __VA_ARGS__);         \
        }                                                                   \
    } while (0)

int main(void) {
    CHECK(offsetof(conn_t, wq_lock) % (size_t)CONN_CACHE_LINE == 0, "%s",
          "wq_lock does not open on a cache-line boundary");
    CHECK(LINE(rcap) < LINE(wq_lock), "%s",
          "a dispatch-only field reaches the handoff lines");
    CHECK(offsetof(conn_t, wcap) - offsetof(conn_t, wq_lock) +
          sizeof(((conn_t *)0)->wcap) <= 2 * (size_t)CONN_CACHE_LINE, "%s",
          "the handoff group no longer fits in two cache lines");
    CHECK(LINE(state) == LINE(wq_lock) || LINE(state) == LINE(wq_lock) + 1, "%s",
          "state left the handoff lines");
    CHECK(LINE(want_write) == LINE(wq_lock) || LINE(want_write) == LINE(wq_lock) + 1, "%s",
          "want_write left the handoff lines");
    if (fails == 0)
        (void)printf("handoff layout: lock@%zu lines %zu-%zu size %zu\n",
                     offsetof(conn_t, wq_lock),
                     LINE(wq_lock), LINE(wcap), sizeof(conn_t));
    return fails != 0;
}
