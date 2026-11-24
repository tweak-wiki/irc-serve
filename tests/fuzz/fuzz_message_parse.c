/* Fuzz harness for the client line parser (issue #533).
 *
 * message_parse_n() is the top remote attack surface: every stranger on the
 * port reaches it through the framing layer. This file feeds it arbitrary
 * bytes and checks the documented contract from src/core/message.h:
 * no crash, no hang, return is 0 or -1, success publishes a sane struct,
 * reject leaves *out zeroed, and message_free() is safe (twice).
 *
 * Two ways to run it, one file:
 *   1. Standalone (what CI runs): fuzz_message_parse [corpus-dir] reads every
 *      file in the corpus dir, then runs a bounded deterministic mutation
 *      sweep over those inputs. Deterministic: same corpus, same result.
 *      FUZZ_ITERS env overrides the mutation budget (default 20000/file).
 *   2. libFuzzer: clang -fsanitize=fuzzer,address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
 *      picks up LLVMFuzzerTestOneInput below for open-ended runs. Not wired
 *      into CMake because AppleClang (the dev machine) ships no libFuzzer;
 *      the standalone path is the portable one CI uses.
 */
#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/message.h"

#ifndef FUZZ_MESSAGE_PARSE_DEFAULT_ITERS
#define FUZZ_MESSAGE_PARSE_DEFAULT_ITERS 20000
#endif

/* Max single input handed to the parser. IRC_MAX_LINE is the on-wire cap;
 * inputs longer than that must be rejected, and feeding far longer ones only
 * burns time in the harness's own fread, not in the parser. */
#define FUZZ_MAX_INPUT (IRC_MAX_LINE + 16)

/* One parse + contract check. Returns 0 when the contract held, 1 when the
 * parser broke it. Never aborts: a broken contract must fail the test, and
 * assert() is the wrong tool in a harness whose job is to report. */
static int fuzz_one(const unsigned char *data, size_t size)
{
    static char line[FUZZ_MAX_INPUT + 1];
    message_t m;

    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }
    if (size > 0) {
        memcpy(line, data, size);
    }
    line[size] = '\0';

    memset(&m, 0, sizeof m);
    int rc = message_parse_n(line, size, &m);
    if (rc != 0 && rc != -1) {
        fprintf(stderr, "fuzz: bad return %d for %zu bytes\n", rc, size);
        return 1;
    }
    if (rc == 0) {
        int bad = 0;
        if (m.command == NULL || m.command[0] == '\0') {
            bad = 1;
        }
        for (const char *p = m.command; !bad && p != NULL && *p != '\0'; p++) {
            if (*p != (char)toupper((unsigned char)*p)) {
                bad = 1; /* 3.2: the command word is uppercased */
            }
        }
        if (m.nparams < 0 || m.nparams > IRC_MAX_PARAMS) {
            bad = 1;
        }
        for (int i = 0; !bad && i < m.nparams; i++) {
            if (m.params[i] == NULL) {
                bad = 1;
            }
        }
        if (m.raw == NULL) {
            bad = 1;
        }
        if (bad) {
            fprintf(stderr, "fuzz: success struct broke contract (%zu bytes)\n", size);
            message_free(&m);
            return 1;
        }
    } else {
        /* Rejection must leave *out zeroed (message.h contract), so the next
         * parse through the same struct cannot inherit a half-built field. */
        if (m.command != NULL || m.prefix != NULL || m.tags != NULL ||
            m.nparams != 0 || m.raw != NULL) {
            fprintf(stderr, "fuzz: reject left a half-built struct (%zu bytes)\n", size);
            message_free(&m);
            return 1;
        }
    }
    /* Safe by contract, and a second call must be safe too. */
    message_free(&m);
    message_free(&m);
    return 0;
}

/* Deterministic xorshift64*: no libc rand() state, same sweep every run. */
static uint64_t rng_next(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * (uint64_t)0x2545F4914F6CDD1DULL;
}

static int failures = 0;
static long iterations = 0;

static void run_one(const unsigned char *data, size_t size)
{
    iterations++;
    failures += fuzz_one(data, size);
}

/* Bounded mutation sweep over one seed: single-byte substitutions, splice
 * points (CR/LF/NUL/':'/'@'/space at every position), truncation, and
 * doubled inputs (the IRC_MAX_LINE boundary). Enough to shake out indexing
 * and termination bugs; libFuzzer entry below is the open-ended upgrade. */
static void sweep_seed(const unsigned char *seed, size_t len, long budget)
{
    static unsigned char mut[FUZZ_MAX_INPUT + 1];
    static const unsigned char interesting[] = {
        '\0', '\r', '\n', ' ', '\t', ':', '@', '!', ';', '#', 'a', 'Z', 0x7f, 0xff
    };
    uint64_t rng = (uint64_t)0x9E3779B97F4A7C15ULL ^ (uint64_t)(len + 1);

    run_one(seed, len);
    for (long i = 0; i < budget && !failures; i++) {
        size_t mlen = len;
        if (len > 0) {
            memcpy(mut, seed, len);
        }
        switch ((unsigned)rng_next(&rng) % 4U) {
        case 0: { /* byte substitution at a random position */
            if (mlen == 0) {
                mut[0] = interesting[rng_next(&rng) % sizeof interesting];
                mlen = 1;
            } else {
                mut[rng_next(&rng) % mlen] =
                    interesting[rng_next(&rng) % sizeof interesting];
            }
            break;
        }
        case 1: { /* truncation (also exercises empty input) */
            mlen = (size_t)(rng_next(&rng) % (uint64_t)(mlen + 1));
            break;
        }
        case 2: { /* insertion of one interesting byte */
            if (mlen < FUZZ_MAX_INPUT) {
                size_t at = mlen == 0 ? 0 : (size_t)(rng_next(&rng) % (uint64_t)(mlen + 1));
                memmove(mut + at + 1, mut + at, mlen - at);
                mut[at] = interesting[rng_next(&rng) % sizeof interesting];
                mlen++;
            }
            break;
        }
        default: { /* doubled seed: straddles the IRC_MAX_LINE cap */
            if (len > 0 && 2 * len <= (size_t)FUZZ_MAX_INPUT) {
                memcpy(mut + len, seed, len);
                mlen = 2 * len;
            }
            break;
        }
        }
        run_one(mut, mlen);
    }
}

static void run_corpus_file(const char *path, long budget)
{
    FILE *f = fopen(path, "rb");
    static unsigned char seed[FUZZ_MAX_INPUT + 1];
    size_t len;
    if (f == NULL) {
        fprintf(stderr, "fuzz: cannot open %s\n", path);
        failures++;
        return;
    }
    len = fread(seed, 1, sizeof seed - 1, f);
    fclose(f);
    sweep_seed(seed, len, budget);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "corpus";
    long budget = (long)FUZZ_MESSAGE_PARSE_DEFAULT_ITERS;
    const char *env = getenv("FUZZ_ITERS");
    DIR *d;
    struct dirent *e;

    if (env != NULL && env[0] != '\0') {
        budget = atol(env);
        if (budget < 0) {
            budget = 0;
        }
    }
    d = opendir(dir);
    if (d == NULL) {
        /* No corpus dir (e.g. run from another cwd): still exercise the
         * parser on the empty input and one fixed seed so the test is never
         * a vacuous pass. */
        static const unsigned char seed[] = ":n!u@h PRIVMSG #c :hi\r\n";
        sweep_seed(NULL, 0, budget);
        sweep_seed(seed, sizeof seed - 1, budget);
    } else {
        int any = 0;
        while ((e = readdir(d)) != NULL) {
            char path[1024];
            if (e->d_name[0] == '.') {
                continue;
            }
            snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
            run_corpus_file(path, budget);
            any = 1;
        }
        closedir(d);
        if (!any) {
            fprintf(stderr, "fuzz: corpus dir %s is empty\n", dir);
            return 1;
        }
    }
    printf("fuzz_message_parse: %ld iterations, %d failures\n", iterations, failures);
    return failures != 0 ? 1 : 0;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)fuzz_one(data, size);
    return 0;
}
#endif
