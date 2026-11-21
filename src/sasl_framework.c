/* sasl_framework.c -- real SASL PLAIN against a real credential store. See
 * sasl_framework.h for the scope decision, the file format, and the timing
 * argument; this file is the implementation of all three.
 *
 * NOTHING HERE PRINTS A CREDENTIAL, and nothing here prints anything at all.
 * The previous version of this file wrote a printf on every state transition,
 * which put the mechanism name and a step counter on stdout but, more to the
 * point, established the habit: the one place in this tree where a secret passes
 * through should be the one place that cannot log. The [observable] lines a node
 * needs are emitted by core/cap.c, which never sees the payload or the password.
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif

#include "sasl_framework.h"
#include "core/secret_util.h"

/* --------------------------------------------------------------------------
 * The store
 * ------------------------------------------------------------------------ */

/* --------------------------------------------------------------------------
 * SHA-256, bundled so the default build stays dependency-free
 * ------------------------------------------------------------------------ */
/* The heap holds salted hashes and never the passwords (see the record below),
 * and that needs a hash in a build that links nothing beyond libc. The TLS
 * backend offers no hash entry point, so plumbing one through it would be a
 * wider change than the property needs; this compact public-domain SHA-256 is
 * the smaller one. Test vector: "abc" -> ba7816bf 8f01cfea 414140de 5dae2223
 * b00361a3 96177a9c b410ff61 f20015ad (checked by inspection, not by a test). */
#define SASL_HASH_LEN 32u
#define SASL_SALT_LEN 16u

typedef struct {
    uint32_t h[8];
    uint64_t total;
    unsigned char block[64];
    size_t used;
} sasl_sha256_t;

static uint32_t sasl_rotr(uint32_t x, unsigned n)
{
    return (uint32_t)((x >> n) | (x << (32u - n)));
}

static void sasl_sha256_block(uint32_t h[8], const unsigned char *p)
{
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t w[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t hh;

    for (size_t i = 0; i < 16u; i++) {
        w[i] = ((uint32_t)p[i * 4u] << 24) | ((uint32_t)p[i * 4u + 1u] << 16) |
               ((uint32_t)p[i * 4u + 2u] << 8) | (uint32_t)p[i * 4u + 3u];
    }
    for (size_t i = 16u; i < 64u; i++) {
        const uint32_t s0 = sasl_rotr(w[i - 15u], 7u) ^
                            sasl_rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        const uint32_t s1 = sasl_rotr(w[i - 2u], 17u) ^
                            sasl_rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);

        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];
    f = h[5];
    g = h[6];
    hh = h[7];
    for (size_t i = 0; i < 64u; i++) {
        const uint32_t s1 =
            sasl_rotr(e, 6u) ^ sasl_rotr(e, 11u) ^ sasl_rotr(e, 25u);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = hh + s1 + ch + k[i] + w[i];
        const uint32_t s0 =
            sasl_rotr(a, 2u) ^ sasl_rotr(a, 13u) ^ sasl_rotr(a, 22u);
        const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = s0 + mj;

        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

static void sasl_sha256_init(sasl_sha256_t *ctx)
{
    ctx->h[0] = 0x6a09e667u;
    ctx->h[1] = 0xbb67ae85u;
    ctx->h[2] = 0x3c6ef372u;
    ctx->h[3] = 0xa54ff53au;
    ctx->h[4] = 0x510e527fu;
    ctx->h[5] = 0x9b05688cu;
    ctx->h[6] = 0x1f83d9abu;
    ctx->h[7] = 0x5be0cd19u;
    ctx->total = 0u;
    ctx->used = 0u;
}

static void sasl_sha256_update(sasl_sha256_t *ctx, const unsigned char *data,
                               size_t len)
{
    ctx->total += (uint64_t)len;
    while (len > 0u) {
        const size_t room = 64u - ctx->used;
        const size_t take = (len < room) ? len : room;

        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        len -= take;
        if (ctx->used == 64u) {
            sasl_sha256_block(ctx->h, ctx->block);
            ctx->used = 0u;
        }
    }
}

static void sasl_sha256_final(sasl_sha256_t *ctx,
                              unsigned char out[SASL_HASH_LEN])
{
    const uint64_t bits = ctx->total * 8u;

    /* 0x80, then zeros until eight bytes remain in the block; when the block
     * fills mid-padding update() flushes it and the count resumes at zero, so
     * this terminates at 56 from either side. The eight length bytes then land
     * exactly. */
    {
        const unsigned char one = 0x80u;
        const unsigned char zero = 0u;

        sasl_sha256_update(ctx, &one, 1u);
        while (ctx->used != 56u) {
            sasl_sha256_update(ctx, &zero, 1u);
        }
    }
    for (size_t i = 0; i < 8u; i++) {
        const unsigned char b =
            (unsigned char)((bits >> (56u - i * 8u)) & 0xffu);

        sasl_sha256_update(ctx, &b, 1u);
    }
    for (size_t i = 0; i < 8u; i++) {
        out[i * 4u] = (unsigned char)((ctx->h[i] >> 24u) & 0xffu);
        out[i * 4u + 1u] = (unsigned char)((ctx->h[i] >> 16u) & 0xffu);
        out[i * 4u + 2u] = (unsigned char)((ctx->h[i] >> 8u) & 0xffu);
        out[i * 4u + 3u] = (unsigned char)(ctx->h[i] & 0xffu);
    }
}

/* Overwrite `n` bytes at `p`. Written through a volatile pointer for the same
 * reason sasl_store_free()'s scrub is: a memset() to memory about to be reused
 * is a store the compiler may prove dead and delete. */
static void sasl_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;

    for (size_t i = 0; i < n; i++) {
        v[i] = 0u;
    }
}

/* One salt per RECORD, generated where the record is created: a boot-wide salt
 * meant identical passwords hashed identically, which told who shared a
 * password. Uniqueness (not secrecy) is all a salt needs, and getentropy()
 * per record is one syscall on a path that runs once per credential. */
static void sasl_gen_salt(unsigned char salt[SASL_SALT_LEN])
{
#if defined(__APPLE__)
    if (getentropy(salt, SASL_SALT_LEN) == 0) {
        return;
    }
    /* getentropy() cannot fail for 16 bytes short of a broken libc, but the
     * salt decides whether two boots' hashes can be told apart, so the
     * fallback is the call that cannot fail rather than a zeroed salt. */
    arc4random_buf(salt, SASL_SALT_LEN);
#else
    if (getentropy(salt, SASL_SALT_LEN) == 0) {
        return;
    }
    {
        FILE *f = fopen("/dev/urandom", "re");

        if (f != NULL) {
            const size_t got = fread(salt, 1u, SASL_SALT_LEN, f);

            (void)fclose(f);
            if (got == SASL_SALT_LEN) {
                return;
            }
        }
    }
    /* Last resort: no kernel RNG and no urandom device. Time, pid and a stack
     * address vary per boot; hashed, they are a unique salt, and uniqueness
     * (not secrecy) is all the record below needs from it. */
    {
        char mix[96];
        sasl_sha256_t ctx;
        unsigned char digest[SASL_HASH_LEN];
        int n = snprintf(mix, sizeof mix, "%llu-%ld-%p",
                         (unsigned long long)time(NULL), (long)getpid(),
                         (void *)mix);

        if (n < 0) {
            mix[0] = '\0';
        }
        sasl_sha256_init(&ctx);
        sasl_sha256_update(&ctx, (const unsigned char *)mix, strlen(mix));
        sasl_sha256_final(&ctx, digest);
        memcpy(salt, digest, SASL_SALT_LEN);
        sasl_wipe(&ctx, sizeof ctx);
        sasl_wipe(digest, sizeof digest);
        sasl_wipe(mix, sizeof mix);
    }
#endif
}

/* --------------------------------------------------------------------------
 * PBKDF2-HMAC-SHA256, and why it is here rather than in a library
 * --------------------------------------------------------------------------
 * Two defects stood here: SHA-256(salt || password) is fast enough to brute
 * force on a GPU, and the salt was generated once per boot, so identical
 * passwords hashed identically and told who shared a password. The fix is a
 * slow KDF under a per-record salt. The default build links nothing beyond
 * libc (see src/CMakeLists.txt's WITH_TLS comment) and the TLS backend
 * offers no KDF entry point, so the lines below are built on this file's own
 * SHA-256 rather than on a new dependency.
 *
 * dkLen is SASL_HASH_LEN (32): exactly one HMAC block, so there is no block
 * index past INT(1) and no output truncation to get wrong. */
#define SASL_PBKDF2_ITER     20000u    /* iterations for every NEW digest */
#define SASL_PBKDF2_ITER_MIN 1000u     /* weakest digest this loader honours */
#define SASL_PBKDF2_ITER_MAX 10000000u /* absurdity bound on a parsed count */

/* The version tag a hashed file record wears, and the rule for recognising
 * one: the password field STARTS WITH this magic. A legacy password that
 * starts with a lone `$` is still plaintext -- only this full prefix enters
 * the hashed arm, and anything wearing it but misshapen is malformed rather
 * than guessed at. */
#define SASL_HASH_MAGIC "$pbkdf2-sha256$"

static void sasl_hmac_sha256(const unsigned char *key, size_t keylen,
                             const unsigned char *data, size_t datalen,
                             unsigned char out[SASL_HASH_LEN])
{
    unsigned char kbuf[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[SASL_HASH_LEN];
    sasl_sha256_t ctx;
    size_t i;

    /* Keys longer than a block hash down; shorter ones zero-pad. Either way
     * the pads below see exactly one block. */
    if (keylen > sizeof kbuf) {
        sasl_sha256_init(&ctx);
        sasl_sha256_update(&ctx, key, keylen);
        sasl_sha256_final(&ctx, kbuf);
        memset(kbuf + SASL_HASH_LEN, 0, sizeof kbuf - SASL_HASH_LEN);
    } else {
        memcpy(kbuf, key, keylen);
        memset(kbuf + keylen, 0, sizeof kbuf - keylen);
    }
    for (i = 0; i < sizeof kbuf; i++) {
        ipad[i] = (unsigned char)(kbuf[i] ^ 0x36u);
        opad[i] = (unsigned char)(kbuf[i] ^ 0x5cu);
    }
    sasl_sha256_init(&ctx);
    sasl_sha256_update(&ctx, ipad, sizeof ipad);
    sasl_sha256_update(&ctx, data, datalen);
    sasl_sha256_final(&ctx, inner);
    sasl_sha256_init(&ctx);
    sasl_sha256_update(&ctx, opad, sizeof opad);
    sasl_sha256_update(&ctx, inner, sizeof inner);
    sasl_sha256_final(&ctx, out);
    /* Key material in five buffers, none of which may outlive the call. */
    sasl_wipe(kbuf, sizeof kbuf);
    sasl_wipe(ipad, sizeof ipad);
    sasl_wipe(opad, sizeof opad);
    sasl_wipe(inner, sizeof inner);
    sasl_wipe(&ctx, sizeof ctx);
}

/* PBKDF2(password, salt, iter, 32). Callers guarantee iter >= 1: fresh digests
 * pass SASL_PBKDF2_ITER and parsed ones passed the MIN bound below. */
static void sasl_pbkdf2(const char *password,
                        const unsigned char salt[SASL_SALT_LEN],
                        unsigned int iter, unsigned char out[SASL_HASH_LEN])
{
    unsigned char msg[SASL_SALT_LEN + 4u];
    unsigned char u[SASL_HASH_LEN];
    unsigned char t[SASL_HASH_LEN];
    size_t pwlen = strlen(password);
    unsigned int i;
    size_t j;

    memcpy(msg, salt, SASL_SALT_LEN);
    msg[SASL_SALT_LEN] = 0u;
    msg[SASL_SALT_LEN + 1u] = 0u;
    msg[SASL_SALT_LEN + 2u] = 0u;
    msg[SASL_SALT_LEN + 3u] = 1u; /* INT(1), big-endian: the only block */
    sasl_hmac_sha256((const unsigned char *)password, pwlen, msg, sizeof msg,
                     u);
    memcpy(out, u, SASL_HASH_LEN);
    for (i = 1u; i < iter; i++) {
        sasl_hmac_sha256((const unsigned char *)password, pwlen, u, sizeof u,
                         t);
        for (j = 0; j < SASL_HASH_LEN; j++) {
            out[j] ^= t[j];
        }
        memcpy(u, t, sizeof u);
    }
    sasl_wipe(msg, sizeof msg);
    sasl_wipe(u, sizeof u);
    sasl_wipe(t, sizeof t);
}

/* The KDF this store hashes under. The heap's only copy of the secret is this
 * digest; the password bytes themselves are never stored. */
static void sasl_hash_password(const unsigned char salt[SASL_SALT_LEN],
                               unsigned int iter, const char *password,
                               unsigned char out[SASL_HASH_LEN])
{
    sasl_pbkdf2(password, salt, iter, out);
}

static int sasl_hex_val(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Decode exactly 2*outlen hex chars; -1 on anything else. Fixed length rather
 * than NUL-terminated so a short field cannot decode to a short salt. */
static int sasl_hex_decode(const char *in, unsigned char *out, size_t outlen)
{
    size_t i;

    for (i = 0; i < outlen; i++) {
        int hi = sasl_hex_val(in[2u * i]);
        int lo = sasl_hex_val(in[2u * i + 1u]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((unsigned)hi << 4u | (unsigned)lo);
    }
    return 0;
}

static void sasl_hex_encode(const unsigned char *in, size_t inlen, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < inlen; i++) {
        out[2u * i] = digits[in[i] >> 4u];
        out[2u * i + 1u] = digits[in[i] & 15u];
    }
    out[2u * inlen] = '\0';
}

/* A record holds a salt and a stretched digest, never a password: the FILE may
 * still carry a legacy plaintext line (0600 enforced at load), but the compat
 * reader re-salts and stretches it on the way in, so what is on the HEAP --
 * and what a dump reads back -- is always salt plus digest. */
struct sasl_record {
    char authcid[SASL_MAX_AUTHCID + 1];
    unsigned char salt[SASL_SALT_LEN]; /* unique per record, stored with it */
    unsigned char phash[SASL_HASH_LEN]; /* PBKDF2(password, salt, iter) */
    unsigned int iter; /* the count this digest was stretched with */
};

struct sasl_store {
    struct sasl_record rec[SASL_MAX_CREDENTIALS];
    size_t n;
};

sasl_store_t *sasl_store_new(void)
{
    return (sasl_store_t *)calloc(1, sizeof(sasl_store_t));
}

void sasl_store_free(sasl_store_t *store)
{
    if (store == NULL) {
        return;
    }
    /* The passwords are overwritten before the memory is released. Not because
     * free() does not do it -- it does -- but because the buffer this allocation
     * came from is reused by the allocator for the next node of the same size,
     * and a credential that is still legible there outlives the record that
     * named it. The cost is one pass over ~13 KB, on a path that runs once. */
    {
        volatile char *p = (volatile char *)store->rec;
        size_t n = sizeof store->rec;
        size_t i = 0;

        /* Written through a volatile pointer so the compiler cannot elide the
         * stores as dead. This is the one place in the tree that says so, and
         * the reason it says so is that the obvious `memset` version gets
         * optimised away. */
        while (i < n) {
            p[i] = 0;
            i++;
        }
    }
    free(store);
}

size_t sasl_store_count(const sasl_store_t *store)
{
    return (store != NULL) ? store->n : 0u;
}

/* ASCII-folded compare, which is how an authcid is matched: an authentication
 * identity is a nickname in every client that offers one, and RFC 2812 2.3.1
 * says nicknames compare case-insensitively. Comparing case-sensitively would
 * let two different records for `Bob` and `bob` both exist and would make the
 * outcome depend on which one the client happened to type. */
static int authcid_eq(const char *a, const char *b)
{
    size_t la = (a != NULL) ? strlen(a) : 0u;
    size_t lb = (b != NULL) ? strlen(b) : 0u;
    size_t n = (la > lb) ? la : lb;
    size_t i;
    unsigned diff = (la != lb) ? 1u : 0u;

    /* Constant-time: a fixed walk over the longer input, no early return, so
     * the comparison cost does not reveal the matching prefix or the length. */
    for (i = 0u; i < n; i++) {
        char ca = (i < la) ? a[i] : (char)0;
        char cb = (i < lb) ? b[i] : (char)0;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        diff |= (unsigned)(ca ^ cb);
    }
    return diff == 0u;
}

/* Slot for authcid: the existing record, or the new tail. (size_t)-1 when the
 * store is full. Split out of sasl_store_add() so the hashed-record path
 * below shares the replace rule rather than reimplementing it. */
static size_t store_slot_for(sasl_store_t *store, const char *authcid)
{
    size_t i;

    for (i = 0; i < store->n; i++) {
        if (authcid_eq(store->rec[i].authcid, authcid) != 0) {
            return i;
        }
    }
    if (store->n >= (size_t)SASL_MAX_CREDENTIALS) {
        return (size_t)-1;
    }
    return store->n;
}

int sasl_store_add(sasl_store_t *store, const char *authcid, const char *password)
{
    size_t alen;
    size_t plen;
    size_t at;

    if (store == NULL || authcid == NULL || password == NULL ||
        authcid[0] == '\0') {
        return -1;
    }
    alen = strlen(authcid);
    plen = strlen(password);
    if (alen > (size_t)SASL_MAX_AUTHCID || plen > (size_t)SASL_MAX_PASSWORD) {
        return -1;
    }
    /* A TAB or a NUL cannot appear in either field: the first is the separator,
     * the second would end the C string and take the rest of the record with it. */
    if (strchr(authcid, '\t') != NULL || strchr(password, '\t') != NULL) {
        return -1;
    }
    at = store_slot_for(store, authcid);
    if (at == (size_t)-1) {
        return -1;
    }
    if (at == store->n) {
        store->n++;
    }
    memcpy(store->rec[at].authcid, authcid, alen + 1u);
    /* Fresh salt per record: two records with the same password hash
     * differently, so the store no longer tells who shares a password. */
    sasl_gen_salt(store->rec[at].salt);
    store->rec[at].iter = SASL_PBKDF2_ITER;
    sasl_hash_password(store->rec[at].salt, SASL_PBKDF2_ITER, password,
                       store->rec[at].phash);
    return 0;
}

/* Install an already-hashed record: the file carried the salt and the digest,
 * so there is nothing to derive. The authcid bound is checked HERE, because
 * this path does not go through sasl_store_add(). */
static int store_put_hashed(sasl_store_t *store, const char *authcid,
                            const unsigned char salt[SASL_SALT_LEN],
                            unsigned int iter,
                            const unsigned char dk[SASL_HASH_LEN])
{
    size_t at;

    if (store == NULL || authcid == NULL || authcid[0] == '\0' ||
        strlen(authcid) > (size_t)SASL_MAX_AUTHCID) {
        return -1;
    }
    at = store_slot_for(store, authcid);
    if (at == (size_t)-1) {
        return -1;
    }
    if (at == store->n) {
        store->n++;
    }
    memcpy(store->rec[at].authcid, authcid, strlen(authcid) + 1u);
    memcpy(store->rec[at].salt, salt, SASL_SALT_LEN);
    memcpy(store->rec[at].phash, dk, SASL_HASH_LEN);
    store->rec[at].iter = iter;
    return 0;
}

/* A hashed file field: `$pbkdf2-sha256$<iter>$<salthex>$<dkhex>`. Every length
 * is exact and iter is bounded: a truncated salt is not a salt, and a count
 * outside MIN..MAX is not this node's KDF. Anything wearing the magic but not
 * shaped like this is malformed -- guessing would promote a corrupted hash
 * into a record no password can ever match, which fails LOUD on every login
 * instead of once at load. */
static int store_parse_hashed(sasl_store_t *store, const char *authcid,
                              const char *field)
{
    const char *p = field + sizeof SASL_HASH_MAGIC - 1u;
    const char *d1 = strchr(p, '$');
    const char *d2;
    unsigned long iter = 0;
    unsigned char salt[SASL_SALT_LEN];
    unsigned char dk[SASL_HASH_LEN];
    int rc = -1;

    if (d1 == NULL || d1 == p) {
        goto out; /* no count, or an empty one */
    }
    for (const char *q = p; q != d1; q++) {
        if (*q < '0' || *q > '9') {
            goto out;
        }
        iter = iter * 10u + (unsigned long)(*q - '0');
        if (iter > (unsigned long)SASL_PBKDF2_ITER_MAX) {
            goto out;
        }
    }
    if (iter < (unsigned long)SASL_PBKDF2_ITER_MIN) {
        goto out;
    }
    d2 = strchr(d1 + 1, '$');
    if (d2 == NULL || (size_t)(d2 - (d1 + 1)) != 2u * SASL_SALT_LEN ||
        strlen(d2 + 1) != 2u * SASL_HASH_LEN) {
        goto out;
    }
    if (sasl_hex_decode(d1 + 1, salt, sizeof salt) != 0 ||
        sasl_hex_decode(d2 + 1, dk, sizeof dk) != 0) {
        goto out;
    }
    rc = store_put_hashed(store, authcid, salt, (unsigned int)iter, dk);
out:
    sasl_wipe(salt, sizeof salt);
    sasl_wipe(dk, sizeof dk);
    return rc;
}

/* Format a file-ready hashed record for authcid/password: the line an
 * operator pastes into --sasl-store's file, and the line tests write into
 * fixture files. Returns 0, or -1 on invalid fields or a too-small `cap`. */
int sasl_store_format_record(const char *authcid, const char *password,
                             char *out, size_t cap)
{
    unsigned char salt[SASL_SALT_LEN];
    unsigned char dk[SASL_HASH_LEN];
    char salthex[2u * SASL_SALT_LEN + 1u];
    char dkhex[2u * SASL_HASH_LEN + 1u];
    int n;
    int rc = -1;

    if (authcid == NULL || password == NULL || out == NULL || cap == 0u ||
        authcid[0] == '\0' || strlen(authcid) > (size_t)SASL_MAX_AUTHCID ||
        strlen(password) > (size_t)SASL_MAX_PASSWORD ||
        strchr(authcid, '\t') != NULL || strchr(password, '\t') != NULL) {
        return -1;
    }
    sasl_gen_salt(salt);
    sasl_hash_password(salt, SASL_PBKDF2_ITER, password, dk);
    sasl_hex_encode(salt, sizeof salt, salthex);
    sasl_hex_encode(dk, sizeof dk, dkhex);
    n = snprintf(out, cap, "%s\t%s%u$%s$%s", authcid, SASL_HASH_MAGIC,
                 SASL_PBKDF2_ITER, salthex, dkhex);
    if (n >= 0 && (size_t)n < cap) {
        rc = 0;
    }
    sasl_wipe(salt, sizeof salt);
    sasl_wipe(dk, sizeof dk);
    sasl_wipe(salthex, sizeof salthex);
    sasl_wipe(dkhex, sizeof dkhex);
    return rc;
}

/* One record per line: `authcid<TAB>password` (legacy: re-salted and stretched
 * on the way in, so the heap never holds what the file held), or
 * `authcid<TAB>$pbkdf2-sha256$...` (the format sasl_store_format_record()
 * writes). Returns 0 on success, -1 on a malformed line. The line is modified
 * in place, so the caller hands it a buffer it owns. */
static int store_parse_line(sasl_store_t *store, char *line)
{
    char *tab = strchr(line, '\t');
    char *value;

    if (tab == NULL) {
        return -1;
    }
    *tab = '\0';
    value = tab + 1;
    /* Trailing CR, because a file written on a machine whose newline is CRLF is
     * an operator's file and not a broken one. Anything else in the password --
     * including a space, which is the whole reason the separator is a TAB -- is
     * the password. */
    {
        size_t vlen = strlen(value);

        while (vlen > 0u && (value[vlen - 1u] == '\r' || value[vlen - 1u] == '\n')) {
            value[--vlen] = '\0';
        }
    }
    if (line[0] == '\0') {
        return -1; /* "TAB password": a record with no authcid */
    }
    if (strncmp(value, SASL_HASH_MAGIC, sizeof SASL_HASH_MAGIC - 1u) == 0) {
        return store_parse_hashed(store, line, value);
    }
    return sasl_store_add(store, line, value);
}

sasl_store_t *sasl_store_load(const char *path)
{
    FILE *f;
    secret_open_status_t open_status = SECRET_OPEN_FAIL_OPEN;
    unsigned open_mode = 0u;
    sasl_store_t *store;
    char line[SASL_MAX_LINE];

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    /* THE SECRET-FILE CHECK, before a byte is read: one shared open
     * (see secret_file_open) whose refusal reasons are the ones below. */
    f = secret_file_open(path, &open_status, &open_mode);
    if (f == NULL) {
        if (open_status == SECRET_OPEN_FAIL_FSTAT) {
            printf("[observable] sasl_store: state=REFUSED path=%s reason=fstat\n", path);
        } else if (open_status == SECRET_OPEN_NOT_REGULAR) {
            printf("[observable] sasl_store: state=REFUSED path=%s reason=not_regular\n",
                   path);
        } else if (open_status == SECRET_OPEN_BAD_MODE) {
            printf("[observable] sasl_store: state=REFUSED path=%s reason=mode_%03o "
                   "(group or other may access a file of passwords)\n",
                   path, open_mode);
        } else {
            printf("[observable] sasl_store: state=REFUSED path=%s reason=open\n", path);
        }
        return NULL;
    }
    store = sasl_store_new();
    if (store == NULL) {
        (void)fclose(f);
        return NULL;
    }

    while (fgets(line, (int)sizeof line, f) != NULL) {
        size_t n = strlen(line);
        char *p = line;

        /* A full buffer with no terminator is over-long, even at EOF:
         * fgets only returns short on newline or EOF, so a full buffer
         * means the line did not fit, trailing newline or not. */
        if (n == sizeof line - 1u && line[n - 1u] != '\n') {
            printf("[observable] sasl_store: state=REFUSED path=%s "
                   "reason=line_too_long\n", path);
            sasl_wipe(line, sizeof line);
            sasl_store_free(store);
            (void)fclose(f);
            return NULL;
        }
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '\n' || *p == '#') {
            continue; /* blank line or comment */
        }
        if (store_parse_line(store, p) != 0) {
            printf("[observable] sasl_store: state=REFUSED path=%s "
                   "reason=malformed_record\n", path);
            sasl_wipe(line, sizeof line);
            sasl_store_free(store);
            (void)fclose(f);
            return NULL;
        }
    }
    if (ferror(f) != 0) {
        printf("[observable] sasl_store: state=REFUSED path=%s reason=read_error\n",
               path);
        sasl_wipe(line, sizeof line);
        sasl_store_free(store);
        (void)fclose(f);
        return NULL;
    }
    /* The line buffer held plaintext passwords; the heap holds only hashes. */
    sasl_wipe(line, sizeof line);
    (void)fclose(f);

    if (store->n == 0u) {
        /* A store with no records authenticates nobody, and reporting it as
         * loaded would make `CAP LS` advertise `sasl` on a node that cannot
         * authenticate a single client -- the exact thing "advertise only what
         * you have" exists to prevent. */
        printf("[observable] sasl_store: state=REFUSED path=%s reason=no_records\n",
               path);
        sasl_store_free(store);
        return NULL;
    }
    printf("[observable] sasl_store: state=LOADED path=%s records=%zu\n", path,
           store->n);
    return store;
}

/* --------------------------------------------------------------------------
 * base64
 * ------------------------------------------------------------------------ */

/* -1 = not in the alphabet, -2 = padding. */
static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    if (c == '=') {
        return -2;
    }
    return -1;
}

static int b64_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
           c == '\v';
}

long sasl_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap)
{
    unsigned long acc = 0;
    int nbits = 0;
    size_t n = 0;
    int saw_pad = 0;

    if (in == NULL || out == NULL) {
        return -1;
    }
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        int v;

        /* Whitespace is skipped rather than refused: clients wrap long
         * AUTHENTICATE payloads at 76 columns, and refusing a wrapped payload
         * refuses irssi. */
        if (b64_is_space(c)) {
            continue;
        }
        if (c == '=') {
            saw_pad = 1;
            continue;
        }
        /* A data byte after padding is a malformed encoding, not a
         * tolerate-it-and-guess case. */
        if (saw_pad != 0) {
            return -1;
        }
        v = b64_value(c);
        if (v < 0) {
            return -1;
        }
        acc = (acc << 6) | (unsigned long)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (n >= cap) {
                return -1; /* insufficient capacity: refuse, never truncate */
            }
            out[n++] = (unsigned char)((acc >> nbits) & 0xFFu);
        }
    }
    /* Leftover bits must be zero. `AB` is 4 bits of data padded with 4 that the
     * encoder should have zeroed; accepting non-zero ones would let two distinct
     * encodings decode to the same credential, which is a way to replay one. */
    if (nbits >= 6) {
        return -1;
    }
    if (nbits > 0 && (acc & ((1UL << nbits) - 1UL)) != 0UL) {
        return -1;
    }
    if (n > (size_t)LONG_MAX) {
        return -1;
    }
    return (long)n;
}

/* --------------------------------------------------------------------------
 * RFC 4616 PLAIN
 * ------------------------------------------------------------------------ */

int sasl_plain_parse(const char *payload, size_t len,
                     char *authzid, size_t authzid_cap,
                     char *authcid, size_t authcid_cap,
                     char *passwd, size_t passwd_cap)
{
    const unsigned char *p = (const unsigned char *)payload;
    size_t z1;
    size_t z2;
    size_t azid_len;
    size_t acid_len;
    size_t pw_len;

    if (authzid != NULL) {
        authzid[0] = '\0';
    }
    if (authcid != NULL) {
        authcid[0] = '\0';
    }
    if (passwd != NULL) {
        passwd[0] = '\0';
    }
    if (payload == NULL) {
        return -1;
    }
    /* Find the two NULs. Scanned as BYTES and not with strchr(), because the
     * payload is not a C string: RFC 4616's format is two NULs by construction,
     * and strchr() would stop at the first one and report no second. */
    z1 = len;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == 0u) {
            z1 = i;
            break;
        }
    }
    if (z1 == len) {
        return -1; /* no first NUL */
    }
    z2 = len;
    for (size_t i = z1 + 1u; i < len; i++) {
        if (p[i] == 0u) {
            z2 = i;
            break;
        }
    }
    if (z2 == len) {
        return -1; /* no second NUL */
    }

    azid_len = z1;
    acid_len = z2 - z1 - 1u;
    pw_len = len - z2 - 1u;

    /* RFC 4013 says an empty authzid means "the same as the authentication
     * identity", and that is how irssi sends it. An authzid that names somebody
     * ELSE is accepted as a field here and then REFUSED by the verify path
     * rather than here, because whether a proxying authzid is permitted is a
     * policy question and this module has no answer to it -- what it must not do
     * is silently treat `alice` authenticating as `bob` by preferring authzid
     * over authcid. sasl_plain_verify() compares against BOTH and requires them
     * to agree, which is the fail-closed direction. */

    if (authcid != NULL) {
        if (authcid_cap == 0u || acid_len + 1u > authcid_cap ||
            acid_len > (size_t)SASL_MAX_AUTHCID) {
            return -1;
        }
        memcpy(authcid, payload + z1 + 1u, acid_len);
        authcid[acid_len] = '\0';
    }
    if (authzid != NULL) {
        if (authzid_cap == 0u || azid_len + 1u > authzid_cap) {
            return -1;
        }
        memcpy(authzid, payload, azid_len);
        authzid[azid_len] = '\0';
    }
    if (passwd != NULL) {
        if (passwd_cap == 0u || pw_len + 1u > passwd_cap ||
            pw_len > (size_t)SASL_MAX_PASSWORD) {
            return -1;
        }
        memcpy(passwd, payload + z2 + 1u, pw_len);
        passwd[pw_len] = '\0';
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Password verification, against the shared constant-time compare
 * ------------------------------------------------------------------------ */

/* A fixed dummy salt and digest, so that "no such authcid" and "wrong
 * password" cost the same: a miss derives under the dummy salt and compares
 * against the dummy digest, paying exactly the one KDF and one comparison a
 * hit pays. Both are constants, not derived values, so neither can leak
 * anything by being computable. */
static const unsigned char dummy_salt[SASL_SALT_LEN] = "irc-serve-dummy";
static const unsigned char dummy_hash[SASL_HASH_LEN] = {
    0x5au, 0x3cu, 0x91u, 0x07u, 0xb2u, 0xe4u, 0x48u, 0xfdu,
    0x1du, 0x66u, 0xa0u, 0xc3u, 0x79u, 0x2bu, 0x8eu, 0x54u,
    0xd6u, 0x0fu, 0x33u, 0x9bu, 0x47u, 0xc1u, 0x5eu, 0xaa,
    0x82u, 0x14u, 0xfbu, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u
};

int sasl_plain_verify(const sasl_store_t *store,
                      const char *authzid, const char *authcid, const char *passwd)
{
    unsigned char want[SASL_HASH_LEN];
    unsigned saw_match = 0u;
    unsigned dummy_used = 0u;
    size_t match = (size_t)-1;

    if (authcid == NULL || authcid[0] == '\0' || passwd == NULL) {
        return 0;
    }
    /* NO STORE, NO AUTHENTICATION. This is the line the previous implementation of
     * this function did not have, and its absence is the defect: a node with
     * nothing to check a password against must refuse every one of them, not
     * accept them. */
    if (store == NULL || store->n == 0u) {
        return 0;
    }
    /* A proxying authzid is refused rather than honoured. `authcid` is what the
     * store is keyed by and `authzid` is what the client asked to act as; when
     * they differ, this node has no policy to allow it and the fail-closed
     * direction is the one that does not require one. An EMPTY authzid is
     * RFC 4013's "same as the authentication identity" and is not a difference. */
    if (authzid != NULL && authzid[0] != '\0' && strcmp(authzid, authcid) != 0) {
        return 0;
    }

    /* The walk runs to the end whether or not anything matched: a walk that
     * stopped at the match would make the answer's latency a function of
     * WHICH record matched, and a client that can time its way down the
     * operator list has turned a credential store into an index. Names are
     * unique (add replaces), so the first match is the record. */
    for (size_t i = 0; i < store->n; i++) {
        if (match == (size_t)-1 &&
            authcid_eq(store->rec[i].authcid, authcid) != 0) {
            match = i;
        }
    }
    /* The offered password is derived ONCE: under the matched record's salt
     * and iteration count -- old records keep verifying under the count they
     * were stretched with -- or under the dummy salt when nothing matched, so
     * a miss pays the same KDF a hit pays. Every comparison below is
     * hash-against-hash, so the timing argument in the header holds over
     * digests exactly as it did over passwords. */
    if (match != (size_t)-1) {
        sasl_hash_password(store->rec[match].salt, store->rec[match].iter,
                           passwd, want);
    } else {
        sasl_hash_password(dummy_salt, SASL_PBKDF2_ITER, passwd, want);
    }
    if (match != (size_t)-1) {
        saw_match |=
            (unsigned)secret_const_time_eq(store->rec[match].phash, want,
                                           SASL_HASH_LEN);
    }
    /* And a miss still pays one comparison, so an authcid that is not in the
     * store is not distinguishable from one whose password is wrong. The
     * compare runs UNCONDITIONALLY -- a hit must cost the same as a miss, so
     * the guard that skipped it on a hit is gone and the result stays ignored. */
    dummy_used =
        (unsigned)secret_const_time_eq(dummy_hash, want, SASL_HASH_LEN);
    (void)dummy_used;
    sasl_wipe(want, sizeof want);
    return (int)(saw_match & 1u);
}

/* --------------------------------------------------------------------------
 * Test support
 * ------------------------------------------------------------------------ */

/* 1 when no byte run in the store's records still equals `password` -- i.e.
 * the heap holds the salted hash and not the literal. A test cannot read the
 * layout (the type is opaque), so this is the predicate that says it. 0 on a
 * NULL store or an empty password, which is the fail-closed answer for a
 * predicate whose whole job is to refuse. */
int sasl_store_holds_no_plaintext(const sasl_store_t *store,
                                  const char *password)
{
    const unsigned char *bytes;
    size_t total;
    size_t plen;

    if (store == NULL || password == NULL || password[0] == '\0') {
        return 0;
    }
    plen = strlen(password);
    bytes = (const unsigned char *)store->rec;
    total = sizeof store->rec;
    if (plen > total) {
        return 1;
    }
    for (size_t i = 0; i + plen <= total; i++) {
        if (memcmp(bytes + i, password, plen) == 0) {
            return 0;
        }
    }
    return 1;
}

/* --------------------------------------------------------------------------
 * The observable state machine
 * ------------------------------------------------------------------------ */

void sasl_init(sasl_ctx_t *ctx, const char *mechanism)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);
    ctx->state = SASL_ABORTED;
    if (mechanism != NULL) {
        const size_t n = strlen(mechanism);

        if (n >= sizeof ctx->mechanism) {
            /* A mechanism name that does not fit is truncated to the field's
             * width, which for the only name this node implements cannot happen
             * and for a longer one produces a name that matches nothing -- so
             * the comparison in sasl_start() refuses it. That is the fail-closed
             * direction and it is why the truncation is safe to leave here. */
            memcpy(ctx->mechanism, mechanism, sizeof ctx->mechanism - 1u);
            ctx->mechanism[sizeof ctx->mechanism - 1u] = '\0';
        } else {
            memcpy(ctx->mechanism, mechanism, n + 1u);
        }
    }
}

void sasl_set_store(sasl_ctx_t *ctx, const sasl_store_t *store)
{
    if (ctx == NULL) {
        return;
    }
    ctx->store = store;
}

static int mech_is_plain(const sasl_ctx_t *ctx)
{
    return strcmp(ctx->mechanism, "PLAIN") == 0;
}

sasl_state_t sasl_start(sasl_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    if (ctx->state != SASL_ABORTED) {
        return ctx->state;
    }
    if (!mech_is_plain(ctx)) {
        /* A mechanism this node does not implement is REFUSED here rather than
         * failing later with a confusing error, and it leaves the state at
         * ABORTED so the caller can offer the list it does implement. */
        ctx->last_error = SASL_ERR_MECH;
        return SASL_FAILED;
    }
    ctx->state = SASL_IN_PROGRESS;
    ctx->step_count = 0;
    return ctx->state;
}

sasl_state_t sasl_step(sasl_ctx_t *ctx, const char *server_data, size_t len,
                       char *client_out, size_t *out_len)
{
    unsigned char payload[SASL_MAX_PAYLOAD];
    char authcid[SASL_MAX_AUTHCID + 1];
    char authzid[SASL_MAX_AUTHCID + 1];
    char passwd[SASL_MAX_PASSWORD + 1];
    long n;

    if (client_out != NULL && out_len != NULL) {
        *out_len = 0;
    }
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    if (ctx->state != SASL_IN_PROGRESS) {
        return ctx->state;
    }
    ctx->step_count++;
    if (!mech_is_plain(ctx)) {
        ctx->last_error = SASL_ERR_MECH;
        ctx->state = SASL_FAILED;
        return ctx->state;
    }

    /* RFC 4422's "the client aborted" is an empty payload. It is an ABORT, not a
     * failure: a client that decides not to authenticate is a client that wants
     * to register, and this node has no operator flags to grant or withhold. */
    if (server_data == NULL || len == 0u) {
        ctx->state = SASL_ABORTED;
        ctx->last_error = SASL_OK;
        return ctx->state;
    }

    n = sasl_b64_decode(server_data, len, payload, sizeof payload);
    if (n < 0) {
        ctx->last_error = SASL_ERR_PAYLOAD;
        ctx->state = SASL_FAILED;
        sasl_wipe(payload, sizeof payload);
        sasl_wipe(passwd, sizeof passwd);
        return ctx->state;
    }
    if (sasl_plain_parse((const char *)payload, (size_t)n, authzid, sizeof authzid,
                         authcid, sizeof authcid, passwd, sizeof passwd) != 0) {
        ctx->last_error = SASL_ERR_PAYLOAD;
        ctx->state = SASL_FAILED;
        sasl_wipe(payload, sizeof payload);
        sasl_wipe(passwd, sizeof passwd);
        return ctx->state;
    }
    /* The decoded identity is recorded on the context -- it is the fact that
     * happened, and a handler needs it to answer 903. The PASSWORD IS NOT, and
     * there is no field for it: `passwd` is a local that is wiped before every
     * return below and is never copied anywhere. A struct that held the
     * password would be a struct a later teardown had to remember to clear. */
    /* The identity is BOUNDED before it is copied rather than truncated after.
     * sasl_plain_parse() has already refused an authcid over
     * SASL_MAX_AUTHCID, and ctx->authcid is 64 wide, so the copy fits; saying so
     * with an explicit length and a NUL is what lets the compiler prove it, which
     * strncpy() cannot. */
    {
        const size_t az = strlen(authzid);
        const size_t ac = strlen(authcid);

        if (az >= sizeof ctx->authzid || ac >= sizeof ctx->authcid) {
            ctx->last_error = SASL_ERR_PAYLOAD;
            ctx->state = SASL_FAILED;
            sasl_wipe(payload, sizeof payload);
            sasl_wipe(passwd, sizeof passwd);
            return ctx->state;
        }
        memcpy(ctx->authzid, authzid, az + 1u);
        memcpy(ctx->authcid, authcid, ac + 1u);
    }

    if (!sasl_plain_verify(ctx->store, authzid, authcid, passwd)) {
        ctx->last_error =
            (ctx->store == NULL || sasl_store_count(ctx->store) == 0u)
                ? SASL_ERR_NO_STORE
                : SASL_ERR_CREDENTIAL;
        ctx->state = SASL_FAILED;
        sasl_wipe(payload, sizeof payload);
        sasl_wipe(passwd, sizeof passwd);
        return ctx->state;
    }
    ctx->last_error = SASL_OK;
    ctx->state = SASL_COMPLETED;
    sasl_wipe(payload, sizeof payload);
    sasl_wipe(passwd, sizeof passwd);
    return ctx->state;
}

sasl_state_t sasl_abort(sasl_ctx_t *ctx, int error_code)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    ctx->state = SASL_ABORTED;
    ctx->last_error = error_code;
    return ctx->state;
}

sasl_state_t sasl_fail(sasl_ctx_t *ctx, int error_code)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    ctx->state = SASL_FAILED;
    ctx->last_error = error_code;
    return ctx->state;
}

sasl_state_t sasl_get_state(const sasl_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    return ctx->state;
}

/* base64 of "authzid\0authcid\0passwd", assembled by hand.
 *
 * Written out rather than borrowed because there is no encoder in this tree and
 * the alternative -- a table of pre-encoded strings in a test -- cannot express
 * the field the test is about. This is TEST-SUPPORT code inside the module
 * because the alternative was a second PLAIN implementation, which is worse. */
static size_t b64_encode(const char *in, size_t len, char *out, size_t cap)
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    size_t n = 0;

    while (i < len) {
        unsigned long acc = 0;
        int have = 0;
        char chunk[4];

        for (int k = 0; k < 3; k++) {
            acc <<= 8;
            if (i < len) {
                acc |= (unsigned long)(unsigned char)in[i++];
                have++;
            }
        }
        chunk[0] = alpha[(acc >> 18) & 0x3Fu];
        chunk[1] = alpha[(acc >> 12) & 0x3Fu];
        chunk[2] = (have > 1) ? alpha[(acc >> 6) & 0x3Fu] : '=';
        chunk[3] = (have > 2) ? alpha[acc & 0x3Fu] : '=';
        for (int k = 0; k < 4; k++) {
            if (n + 1u >= cap) {
                return 0;
            }
            out[n++] = chunk[k];
        }
    }
    if (cap == 0) {
        return 0;
    }
    out[n] = '\0';
    return n;
}

/* Build "authzid\0authcid\0passwd" into `buf`. Returns its length, or 0 if it
 * does not fit. */
static size_t plain_build(char *buf, size_t cap, const char *authzid,
                          const char *authcid, const char *passwd)
{
    const size_t za = strlen(authzid);
    const size_t zc = strlen(authcid);
    const size_t zp = strlen(passwd);
    size_t n = 0;

    if (za + 1u + zc + 1u + zp > cap) {
        return 0;
    }
    memcpy(buf + n, authzid, za);
    n += za;
    buf[n++] = '\0';
    memcpy(buf + n, authcid, zc);
    n += zc;
    buf[n++] = '\0';
    memcpy(buf + n, passwd, zp);
    n += zp;
    return n;
}

int sasl_state_machine(void)
{
    sasl_store_t *store = sasl_store_new();
    sasl_ctx_t ctx;
    char payload[512];
    char encoded[700];
    size_t plen;
    size_t elen;
    int ok = 1;

    if (store == NULL) {
        return 0;
    }
    if (sasl_store_add(store, "alice", "correct horse") != 0 ||
        sasl_store_add(store, "bob", "s3cret") != 0 ||
        sasl_store_count(store) != 2u) {
        sasl_store_free(store);
        return 0;
    }

    /* 1. THE GOOD PATH. A correct credential reaches COMPLETED and the context
     *    holds the identity that authenticated. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    ok &= (sasl_start(&ctx) == SASL_IN_PROGRESS);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (elen > 0);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_COMPLETED);
    ok &= (strcmp(ctx.authcid, "alice") == 0);

    /* 2. A WRONG PASSWORD reaches FAILED. This is the case the previous
     *    implementation of this file could not produce: it marked the exchange
     *    COMPLETED on the second step without ever looking at the bytes. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "wrong");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_CREDENTIAL);

    /* 3. A WRONG PASSWORD that is a PREFIX of the right one also fails, which
     *    is the case a prefix comparison would get wrong. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);

    /* 4. AN UNKNOWN AUTHCID fails, and is indistinguishable from #2 by result. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "mallory", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_CREDENTIAL);

    /* 5. THE AUTHZID MUST NOT OVERRIDE THE AUTHCID. `alice` may not authenticate
     *    as `bob`, which is what a store lookup on authzid would have done. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "bob", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);

    /* 6. NO STORE, NO AUTHENTICATION. The line whose absence was the defect. */
    sasl_init(&ctx, "PLAIN");
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_NO_STORE);

    /* 7. A MALFORMED PAYLOAD fails without ever reaching the store. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    ok &= (sasl_step(&ctx, "not base64 !!", 13, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_PAYLOAD);
    /* base64 of "no NULs here" */
    ok &= (sasl_step(&ctx, "bm8gTlVMUyBoZXJl", 16, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_PAYLOAD);

    /* 8. A MECHANISM THIS NODE DOES NOT IMPLEMENT is refused, and it never
     *    reaches IN_PROGRESS -- so no client is told to send a PLAIN payload to
     *    a server that cannot verify one. */
    sasl_init(&ctx, "SCRAM-SHA-256");
    sasl_set_store(&ctx, store);
    ok &= (sasl_start(&ctx) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_MECH);

    /* 9. AN EMPTY PAYLOAD IS AN ABORT (RFC 4422), not a failure, and it does not
     *    complete the exchange either. A client that declines to authenticate
     *    must still be able to register. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    ok &= (sasl_step(&ctx, "", 0, NULL, NULL) == SASL_ABORTED);

    /* 10. A SECOND step in a terminal state returns that state. This is the
     *     exact case the previous implementation had backwards: it advanced on
     *     the second CALL, so calling step twice completed an exchange that had
     *     been sent nothing at all. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_COMPLETED);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_COMPLETED);

    /* 11. Base64 itself: padding, whitespace, and a refusal rather than a
     *     truncation when the output does not fit. */
    {
        unsigned char out[8];
        long n = sasl_b64_decode("YQ==", 4, out, sizeof out);

        ok &= (n == 1 && out[0] == (unsigned char)'a');
        /* A wrapped payload -- irssi wraps at 76 columns -- decodes to the same
         * five bytes ("alxce"), because the whitespace is skipped rather than
         * refused. The buffer is 8 wide on purpose: a decoder that refused the
         * wrap would also answer -1 here, so a 3-wide buffer is what tells the
         * two apart. */
        {
            unsigned char tight[3];

            /* The decoded text is "alace": five bytes, and a decoder that
             * stopped at the CR would have produced three. */
            n = sasl_b64_decode("YWxh\r\n Y2U=", 11, out, sizeof out);
            ok &= (n == 5 && memcmp(out, "alace", 5) == 0);
            /* And it refuses rather than truncating when the output is too
             * small, which is what 3.2's rule is for. */
            ok &= (sasl_b64_decode("YWxh\r\n Y2U=", 11, tight, sizeof tight) == -1);
        }
        ok &= (sasl_b64_decode("YQ==", 4, out, 0) == -1);
        ok &= (sasl_b64_decode("****", 4, out, sizeof out) == -1);
        /* Data after padding is malformed, not tolerated. */
        ok &= (sasl_b64_decode("YQ==YQ==", 8, out, sizeof out) == -1);
        ok &= (sasl_b64_decode("YQ", 2, out, sizeof out) == 1);
        /* Non-zero leftover bits are refused: two encodings, one credential. */
        ok &= (sasl_b64_decode("YR==", 4, out, sizeof out) == -1);
    }

    sasl_store_free(store);
    return ok;
}
