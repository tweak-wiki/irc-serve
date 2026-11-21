/* account_store.c -- the account registry. See account_store.h for the format,
 * the secret-file discipline, and the argument for why this is a separate file
 * from the credential store.
 *
 * NOTHING HERE PRINTS A PASSWORD, and nothing here prints a whole record
 * either -- the [observable] lines name the PATH and the COUNT, and a store with
 * one credential in it has the same log output as one with sixty-four. The
 * discipline is the one sasl_framework.c established: the module a secret passes
 * through is the module that cannot log.
 */
#include "account_store.h"

#include "core/secret_util.h"


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

/* --------------------------------------------------------------------------
 * SHA-256, bundled so the default build stays dependency-free
 * ------------------------------------------------------------------------ */
/* The heap holds salted hashes and never the passwords (see the record below),
 * and that needs a hash in a build that links nothing beyond libc. Copied
 * from sasl_framework.c rather than shared, for the reason the scrub pass
 * below is a copy too: the two stores keep no shared state beyond the secret
 * open and the digest comparison (see core/secret_util.h). Test vector: "abc"
 * -> ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad. */
#define ACCOUNT_HASH_LEN 32u
#define ACCOUNT_SALT_LEN 16u

typedef struct {
    uint32_t h[8];
    uint64_t total;
    unsigned char block[64];
    size_t used;
} account_sha256_t;

static uint32_t account_rotr(uint32_t x, unsigned n)
{
    return (uint32_t)((x >> n) | (x << (32u - n)));
}

static void account_sha256_block(uint32_t h[8], const unsigned char *p)
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
        const uint32_t s0 = account_rotr(w[i - 15u], 7u) ^
                            account_rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        const uint32_t s1 = account_rotr(w[i - 2u], 17u) ^
                            account_rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);

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
            account_rotr(e, 6u) ^ account_rotr(e, 11u) ^ account_rotr(e, 25u);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = hh + s1 + ch + k[i] + w[i];
        const uint32_t s0 =
            account_rotr(a, 2u) ^ account_rotr(a, 13u) ^ account_rotr(a, 22u);
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

static void account_sha256_init(account_sha256_t *ctx)
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

static void account_sha256_update(account_sha256_t *ctx,
                                  const unsigned char *data, size_t len)
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
            account_sha256_block(ctx->h, ctx->block);
            ctx->used = 0u;
        }
    }
}

static void account_sha256_final(account_sha256_t *ctx,
                                 unsigned char out[ACCOUNT_HASH_LEN])
{
    const uint64_t bits = ctx->total * 8u;

    /* 0x80, then zeros until eight bytes remain in the block; when the block
     * fills mid-padding update() flushes it and the count resumes at zero, so
     * this terminates at 56 from either side. The eight length bytes then land
     * exactly. */
    {
        const unsigned char one = 0x80u;
        const unsigned char zero = 0u;

        account_sha256_update(ctx, &one, 1u);
        while (ctx->used != 56u) {
            account_sha256_update(ctx, &zero, 1u);
        }
    }
    for (size_t i = 0; i < 8u; i++) {
        const unsigned char b =
            (unsigned char)((bits >> (56u - i * 8u)) & 0xffu);

        account_sha256_update(ctx, &b, 1u);
    }
    for (size_t i = 0; i < 8u; i++) {
        out[i * 4u] = (unsigned char)((ctx->h[i] >> 24u) & 0xffu);
        out[i * 4u + 1u] = (unsigned char)((ctx->h[i] >> 16u) & 0xffu);
        out[i * 4u + 2u] = (unsigned char)((ctx->h[i] >> 8u) & 0xffu);
        out[i * 4u + 3u] = (unsigned char)(ctx->h[i] & 0xffu);
    }
}

/* Overwrite `n` bytes at `p`. Written through a volatile pointer for the same
 * reason account_store_free()'s scrub is: a memset() to memory about to be
 * reused is a store the compiler may prove dead and delete. */
static void account_wipe(void *p, size_t n)
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
static void account_gen_salt(unsigned char salt[ACCOUNT_SALT_LEN])
{
#if defined(__APPLE__)
    if (getentropy(salt, ACCOUNT_SALT_LEN) == 0) {
        return;
    }
    /* getentropy() cannot fail for 16 bytes short of a broken libc, but the
     * salt decides whether two boots' hashes can be told apart, so the
     * fallback is the call that cannot fail rather than a zeroed salt. */
    arc4random_buf(salt, ACCOUNT_SALT_LEN);
#else
    if (getentropy(salt, ACCOUNT_SALT_LEN) == 0) {
        return;
    }
    {
        FILE *f = fopen("/dev/urandom", "re");

        if (f != NULL) {
            const size_t got = fread(salt, 1u, ACCOUNT_SALT_LEN, f);

            (void)fclose(f);
            if (got == ACCOUNT_SALT_LEN) {
                return;
            }
        }
    }
    /* Last resort: no kernel RNG and no urandom device. Time, pid and a stack
     * address vary per boot; hashed, they are a unique salt, and uniqueness
     * (not secrecy) is all the record below needs from it. */
    {
        char mix[96];
        account_sha256_t ctx;
        unsigned char digest[ACCOUNT_HASH_LEN];
        int n = snprintf(mix, sizeof mix, "%llu-%ld-%p",
                         (unsigned long long)time(NULL), (long)getpid(),
                         (void *)mix);

        if (n < 0) {
            mix[0] = '\0';
        }
        account_sha256_init(&ctx);
        account_sha256_update(&ctx, (const unsigned char *)mix, strlen(mix));
        account_sha256_final(&ctx, digest);
        memcpy(salt, digest, ACCOUNT_SALT_LEN);
        account_wipe(&ctx, sizeof ctx);
        account_wipe(digest, sizeof digest);
        account_wipe(mix, sizeof mix);
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
 * dkLen is ACCOUNT_HASH_LEN (32): exactly one HMAC block, so there is no
 * block index past INT(1) and no output truncation to get wrong. */
#define ACCOUNT_PBKDF2_ITER     20000u    /* iterations for every NEW digest */
#define ACCOUNT_PBKDF2_ITER_MIN 1000u     /* weakest digest this loader honours */
#define ACCOUNT_PBKDF2_ITER_MAX 10000000u /* absurdity bound on a parsed count */

/* The version tag a hashed file record wears; see sasl_framework.c's
 * SASL_HASH_MAGIC for the recognition rule, which this module shares: only
 * the full prefix enters the hashed arm. */
#define ACCOUNT_HASH_MAGIC "$pbkdf2-sha256$"

static void account_hmac_sha256(const unsigned char *key, size_t keylen,
                                const unsigned char *data, size_t datalen,
                                unsigned char out[ACCOUNT_HASH_LEN])
{
    unsigned char kbuf[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[ACCOUNT_HASH_LEN];
    account_sha256_t ctx;
    size_t i;

    /* Keys longer than a block hash down; shorter ones zero-pad. Either way
     * the pads below see exactly one block. */
    if (keylen > sizeof kbuf) {
        account_sha256_init(&ctx);
        account_sha256_update(&ctx, key, keylen);
        account_sha256_final(&ctx, kbuf);
        memset(kbuf + ACCOUNT_HASH_LEN, 0, sizeof kbuf - ACCOUNT_HASH_LEN);
    } else {
        memcpy(kbuf, key, keylen);
        memset(kbuf + keylen, 0, sizeof kbuf - keylen);
    }
    for (i = 0; i < sizeof kbuf; i++) {
        ipad[i] = (unsigned char)(kbuf[i] ^ 0x36u);
        opad[i] = (unsigned char)(kbuf[i] ^ 0x5cu);
    }
    account_sha256_init(&ctx);
    account_sha256_update(&ctx, ipad, sizeof ipad);
    account_sha256_update(&ctx, data, datalen);
    account_sha256_final(&ctx, inner);
    account_sha256_init(&ctx);
    account_sha256_update(&ctx, opad, sizeof opad);
    account_sha256_update(&ctx, inner, sizeof inner);
    account_sha256_final(&ctx, out);
    /* Key material in five buffers, none of which may outlive the call. */
    account_wipe(kbuf, sizeof kbuf);
    account_wipe(ipad, sizeof ipad);
    account_wipe(opad, sizeof opad);
    account_wipe(inner, sizeof inner);
    account_wipe(&ctx, sizeof ctx);
}

/* PBKDF2(password, salt, iter, 32). Callers guarantee iter >= 1: fresh digests
 * pass ACCOUNT_PBKDF2_ITER and parsed ones passed the MIN bound below. */
static void account_pbkdf2(const char *password,
                           const unsigned char salt[ACCOUNT_SALT_LEN],
                           unsigned int iter, unsigned char out[ACCOUNT_HASH_LEN])
{
    unsigned char msg[ACCOUNT_SALT_LEN + 4u];
    unsigned char u[ACCOUNT_HASH_LEN];
    unsigned char t[ACCOUNT_HASH_LEN];
    size_t pwlen = strlen(password);
    unsigned int i;
    size_t j;

    memcpy(msg, salt, ACCOUNT_SALT_LEN);
    msg[ACCOUNT_SALT_LEN] = 0u;
    msg[ACCOUNT_SALT_LEN + 1u] = 0u;
    msg[ACCOUNT_SALT_LEN + 2u] = 0u;
    msg[ACCOUNT_SALT_LEN + 3u] = 1u; /* INT(1), big-endian: the only block */
    account_hmac_sha256((const unsigned char *)password, pwlen, msg,
                        sizeof msg, u);
    memcpy(out, u, ACCOUNT_HASH_LEN);
    for (i = 1u; i < iter; i++) {
        account_hmac_sha256((const unsigned char *)password, pwlen, u,
                            sizeof u, t);
        for (j = 0; j < ACCOUNT_HASH_LEN; j++) {
            out[j] ^= t[j];
        }
        memcpy(u, t, sizeof u);
    }
    account_wipe(msg, sizeof msg);
    account_wipe(u, sizeof u);
    account_wipe(t, sizeof t);
}

/* The KDF this registry hashes under. The heap's only copy of the secret is
 * this digest; the password bytes themselves are never stored. */
static void account_hash_password(const unsigned char salt[ACCOUNT_SALT_LEN],
                                  unsigned int iter, const char *password,
                                  unsigned char out[ACCOUNT_HASH_LEN])
{
    account_pbkdf2(password, salt, iter, out);
}

static int account_hex_val(char c)
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
static int account_hex_decode(const char *in, unsigned char *out, size_t outlen)
{
    size_t i;

    for (i = 0; i < outlen; i++) {
        int hi = account_hex_val(in[2u * i]);
        int lo = account_hex_val(in[2u * i + 1u]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((unsigned)hi << 4u | (unsigned)lo);
    }
    return 0;
}

static void account_hex_encode(const unsigned char *in, size_t inlen, char *out)
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
struct account_record {
    char name[ACCOUNT_MAX_NAME + 1];
    unsigned char salt[ACCOUNT_SALT_LEN]; /* unique per record, stored with it */
    unsigned char phash[ACCOUNT_HASH_LEN]; /* PBKDF2(password, salt, iter) */
    unsigned int iter; /* the count this digest was stretched with */
    long created;
};

struct account_store {
    struct account_record rec[ACCOUNT_MAX_RECORDS];
    size_t n;
};

/* ASCII-folded compare, for the same reason sasl_framework.c's authcid_eq()
 * exists: an account name is a nickname in every client that displays one, and
 * RFC 2812 2.3.1 says nicknames compare case-insensitively. Comparing
 * case-sensitively would let `Alice` and `alice` both exist, and which one a
 * client authenticated as would then decide what other users are shown. */
static int name_eq(const char *a, const char *b)
{
    size_t la = (a != NULL) ? strlen(a) : 0u;
    size_t lb = (b != NULL) ? strlen(b) : 0u;
    size_t n = (la > lb) ? la : lb;
    size_t i;
    unsigned diff = (la != lb) ? 1u : 0u;

    /* Constant-time, like sasl_framework.c's authcid_eq(). */
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

/* Parse a decimal integer that must consume the WHOLE string. strtol() alone
 * accepts "1700000000junk" and stops, and a `created` column that silently
 * became the leading digits would be a wrong fact in a file whose whole purpose
 * is to be a readable record. Returns 0 on success, -1 otherwise. */
static int parse_created(const char *text, long *out)
{
    char *end = NULL;
    long value;

    if (text == NULL || text[0] == '\0') {
        return -1;
    }
    for (const char *p = text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    value = strtol(text, &end, 10);
    if (end == NULL || *end != '\0') {
        return -1;
    }
    *out = value;
    return 0;
}

account_store_t *account_store_new(void)
{
    return (account_store_t *)calloc(1, sizeof(account_store_t));
}
void account_store_free(account_store_t *store)
{
    if (store == NULL) {
        return;
    }
    /* THE PASSWORDS ARE OVERWRITTEN BEFORE THE MEMORY IS RELEASED, and this is
     * not ceremony. free() does scrub nothing -- it hands the buffer back -- but
     * the allocator reuses that buffer for the next node of the same size, so a
     * password still legible there outlives the record that named it by an
     * arbitrary length of time.
     *
     * THE `volatile` IS THE POINT and it is not decorative: the compiler is
     * entitled to see a block of stores to memory it is about to release, prove
     * the values are dead, and delete the writes. sasl_store_free() carries the
     * identical pass for the identical reason, and this is the second copy
     * rather than a shared helper on purpose -- see the note in the block
     * comment below.
     *
     * WHY A COPY AND NOT A HELPER, since the argument has been made elsewhere in
     * this tree (the federation modules' ASCII fold) and the answer here is different:
     * the two stores are separate FILES, and a shared scrub helper would put a
     * function in one of them that the other had to link -- which is the same
     * coupling that account_store.h argues against for the records themselves.
     * Six lines, written twice, is cheaper than a module boundary crossed to
     * save six lines. */
    {
        volatile char *p = (volatile char *)store->rec;
        const size_t n = sizeof store->rec;
        size_t i = 0;

        while (i < n) {
            p[i] = 0;
            i++;
        }
    }
    free(store);
}

size_t account_store_count(const account_store_t *store)
{
    return (store != NULL) ? store->n : 0u;
}

int account_name_wire_safe(const char *name)
{
    size_t i;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    /* AND THE LENGTH, WHICH IS PART OF THE SAME RULE AND WAS MISSING FROM IT.
     *
     * Every field this name reaches is ACCOUNT_MAX_NAME wide -- conn_t::account,
     * chan_remote_t::account, burst_member_t::account -- and a name longer than
     * that is one this node cannot HOLD, which is a stronger statement than one
     * it cannot render. Rendering was the whole of the predicate when there were
     * two callers, both of them on the LOCAL side: account_set() and
     * account_store_add(), and both already bounded the length separately. The
     * two PEER-side callers came with Phase 10.3 and neither had anywhere to
     * bound it, because the rule they were handed says nothing about length:
     *
     *   chan_remote_add()  copy_bounded() TRUNCATES and returns 0, which both call
     *                      sites discard -- so the roster ended up holding a
     *                      DIFFERENT NAME from the one the peer reported, under a
     *                      name that peer will never be asked about again.
     *   burst.c's apply_member()  burst_copy() REFUSES rather than truncating, and
     *                      writes NOTHING -- into a slot of a realloc'd array that
     *                      nothing zeroes. So what the resync went on to install
     *                      was whatever the allocator had left there.
     *
     * Both are the same defect seen from two receivers, and both are closed by
     * one bound in one place, which is what this predicate is FOR: the account
     * header's argument is that a name it refuses is a name no connection can be
     * logged in as, and a name that does not FIT is a name no field can hold,
     * whichever of the two the caller happened to notice.
     *
     * The bound is ACCOUNT_MAX_NAME and not a literal, for the reason the constant
     * is documented with: it is "conn_t::account's bound minus one", so the three
     * fields and the predicate cannot come to disagree about where the edge is. */
    if (strlen(name) > (size_t)ACCOUNT_MAX_NAME) {
        return 0;
    }
    if (name[0] == ':') {
        /* A LEADING colon is the marker 3.2 writes itself; a value that starts
         * with one cannot be told apart from a marker by a parser, and
         * message_format() refuses such a value in every position but the last.
         * The `*` case is the exception and is the reason it is not simply "a
         * colon is bad". */
        return (name[1] == '\0') ? 1 : 0;
    }
    for (i = 0; name[i] != '\0'; i++) {
        const unsigned char ch = (unsigned char)name[i];

        if (ch <= 0x20u || ch == 0x7fu) {
            /* SP, HTAB, CR, LF, every other control byte, and DEL. 3.2 refuses all
             * of them in a parameter, and a parameter is where three of the four
             * places this name appears have to put it. */
            return 0;
        }
    }
    return 1;
}

/* Slot for name: the existing record, or the new tail. (size_t)-1 when the
 * registry is full. Split out of account_store_add() so the hashed-record
 * path below shares the replace rule rather than reimplementing it. */
static size_t store_slot_for(account_store_t *store, const char *name)
{
    size_t i;

    for (i = 0; i < store->n; i++) {
        if (name_eq(store->rec[i].name, name) != 0) {
            return i;
        }
    }
    if (store->n >= (size_t)ACCOUNT_MAX_RECORDS) {
        return (size_t)-1;
    }
    return store->n;
}

int account_store_add(account_store_t *store, const char *name,
                      const char *password, long created)
{
    size_t nlen;
    size_t plen;
    size_t at;

    if (store == NULL || name == NULL || password == NULL || name[0] == '\0') {
        return -1;
    }
    nlen = strlen(name);
    plen = strlen(password);
    if (nlen > (size_t)ACCOUNT_MAX_NAME || plen > (size_t)ACCOUNT_MAX_PASSWORD) {
        return -1;
    }
    /* A TAB cannot appear in either field: the first is the separator and the
     * second is what would follow it. A SPACE in the PASSWORD is allowed and is
     * the reason the separator is a TAB rather than a split on whitespace --
     * sasl_store_add() makes the same call for the same reason.
     *
     * AND THE NAME MUST BE PUBLISHABLE, which is the one asymmetry between the two
     * fields and it is Phase 10.3 that made it visible. A password never leaves
     * this process; an account name is a middle parameter of 330 RPL_WHOISACCOUNT,
     * of the JOIN echo and of two S-verbs, and 3.2 can escape nothing in a
     * parameter. account_name_wire_safe() is the rule and account.h is where it is
     * argued; enforcing it HERE rather than only at the renderer is what makes a
     * registry unable to contain a name this node could never show a user.
     *
     * `*` is accepted, because it is what the protocol reserves for "no account"
     * and refusing it here would make a registry unable to hold the one name the
     * wire uses for the absence. */
    if (strchr(password, '\t') != NULL || account_name_wire_safe(name) == 0) {
        return -1;
    }
    at = store_slot_for(store, name);
    if (at == (size_t)-1) {
        return -1;
    }
    if (at == store->n) {
        store->n++;
    }
    memcpy(store->rec[at].name, name, nlen + 1u);
    /* Fresh salt per record: two records with the same password hash
     * differently, so the registry no longer tells who shares a password. */
    account_gen_salt(store->rec[at].salt);
    store->rec[at].iter = ACCOUNT_PBKDF2_ITER;
    account_hash_password(store->rec[at].salt, ACCOUNT_PBKDF2_ITER, password,
                          store->rec[at].phash);
    store->rec[at].created = created;
    return 0;
}

/* Install an already-hashed record: the file carried the salt and the digest,
 * so there is nothing to derive. The name rules are checked HERE, because
 * this path does not go through account_store_add(). */
static int store_put_hashed(account_store_t *store, const char *name,
                            const unsigned char salt[ACCOUNT_SALT_LEN],
                            unsigned int iter,
                            const unsigned char dk[ACCOUNT_HASH_LEN],
                            long created)
{
    size_t at;

    if (store == NULL || name == NULL || account_name_wire_safe(name) == 0) {
        return -1;
    }
    at = store_slot_for(store, name);
    if (at == (size_t)-1) {
        return -1;
    }
    if (at == store->n) {
        store->n++;
    }
    memcpy(store->rec[at].name, name, strlen(name) + 1u);
    memcpy(store->rec[at].salt, salt, ACCOUNT_SALT_LEN);
    memcpy(store->rec[at].phash, dk, ACCOUNT_HASH_LEN);
    store->rec[at].iter = iter;
    store->rec[at].created = created;
    return 0;
}

/* A hashed password field: `$pbkdf2-sha256$<iter>$<salthex>$<dkhex>`. Every
 * length is exact and iter is bounded, for the reason sasl_framework.c's
 * store_parse_hashed() gives: anything wearing the magic but not shaped like
 * this is malformed, never guessed at. */
static int store_parse_hashed(account_store_t *store, const char *name,
                              const char *field, long created)
{
    const char *p = field + sizeof ACCOUNT_HASH_MAGIC - 1u;
    const char *d1 = strchr(p, '$');
    const char *d2;
    unsigned long iter = 0;
    unsigned char salt[ACCOUNT_SALT_LEN];
    unsigned char dk[ACCOUNT_HASH_LEN];
    int rc = -1;

    if (d1 == NULL || d1 == p) {
        goto out; /* no count, or an empty one */
    }
    for (const char *q = p; q != d1; q++) {
        if (*q < '0' || *q > '9') {
            goto out;
        }
        iter = iter * 10u + (unsigned long)(*q - '0');
        if (iter > (unsigned long)ACCOUNT_PBKDF2_ITER_MAX) {
            goto out;
        }
    }
    if (iter < (unsigned long)ACCOUNT_PBKDF2_ITER_MIN) {
        goto out;
    }
    d2 = strchr(d1 + 1, '$');
    if (d2 == NULL || (size_t)(d2 - (d1 + 1)) != 2u * ACCOUNT_SALT_LEN ||
        strlen(d2 + 1) != 2u * ACCOUNT_HASH_LEN) {
        goto out;
    }
    if (account_hex_decode(d1 + 1, salt, sizeof salt) != 0 ||
        account_hex_decode(d2 + 1, dk, sizeof dk) != 0) {
        goto out;
    }
    rc = store_put_hashed(store, name, salt, (unsigned int)iter, dk, created);
out:
    account_wipe(salt, sizeof salt);
    account_wipe(dk, sizeof dk);
    return rc;
}

/* Format a file-ready hashed record for `name`/`password`/`created`: the line
 * an operator pastes into --account-store's file, and the line tests write
 * into fixture files. The salt is fresh per call, so two calls with the same
 * password produce different lines. Returns 0, or -1 on invalid fields or a
 * too-small `cap`. */
int account_store_format_record(const char *name, const char *password,
                                long created, char *out, size_t cap)
{
    unsigned char salt[ACCOUNT_SALT_LEN];
    unsigned char dk[ACCOUNT_HASH_LEN];
    char salthex[2u * ACCOUNT_SALT_LEN + 1u];
    char dkhex[2u * ACCOUNT_HASH_LEN + 1u];
    int n;
    int rc = -1;

    if (name == NULL || password == NULL || out == NULL || cap == 0u ||
        account_name_wire_safe(name) == 0 ||
        strlen(password) > (size_t)ACCOUNT_MAX_PASSWORD ||
        strchr(password, '\t') != NULL) {
        return -1;
    }
    account_gen_salt(salt);
    account_hash_password(salt, ACCOUNT_PBKDF2_ITER, password, dk);
    account_hex_encode(salt, sizeof salt, salthex);
    account_hex_encode(dk, sizeof dk, dkhex);
    n = snprintf(out, cap, "%s\t%s%u$%s$%s\t%ld", name, ACCOUNT_HASH_MAGIC,
                 ACCOUNT_PBKDF2_ITER, salthex, dkhex, created);
    if (n >= 0 && (size_t)n < cap) {
        rc = 0;
    }
    account_wipe(salt, sizeof salt);
    account_wipe(dk, sizeof dk);
    account_wipe(salthex, sizeof salthex);
    account_wipe(dkhex, sizeof dkhex);
    return rc;
}

/* A fixed dummy salt and digest, so that "no such account" and "wrong
 * password" cost the same: a miss derives under the dummy salt and compares
 * against the dummy digest, paying exactly the one KDF and one comparison a
 * hit pays. Both are constants, not derived values, so neither can leak
 * anything by being computable. */
static const unsigned char dummy_salt[ACCOUNT_SALT_LEN] = "irc-serve-dummy";
static const unsigned char dummy_hash[ACCOUNT_HASH_LEN] = {
    0x5au, 0x3cu, 0x91u, 0x07u, 0xb2u, 0xe4u, 0x48u, 0xfdu,
    0x1du, 0x66u, 0xa0u, 0xc3u, 0x79u, 0x2bu, 0x8eu, 0x54u,
    0xd6u, 0x0fu, 0x33u, 0x9bu, 0x47u, 0xc1u, 0x5eu, 0xaau,
    0x82u, 0x14u, 0xfbu, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u
};

int account_store_verify(const account_store_t *store, const char *name,
                         const char *password)
{
    unsigned char want[ACCOUNT_HASH_LEN];
    unsigned saw_match = 0u;
    unsigned dummy_used = 0u;
    size_t match = (size_t)-1;

    if (name == NULL || name[0] == '\0' || password == NULL) {
        return 0;
    }
    /* NO REGISTRY, NO ACCOUNT CLAIM. The fail-closed direction, and the reason a
     * node started without --account-store cannot have a logged-in client even
     * if its credential store would verify one: there is nothing on this node
     * that says the account exists. */
    if (store == NULL || store->n == 0u) {
        return 0;
    }
    /* The walk runs to the end whether or not anything matched: a walk that
     * stopped at the match would make the answer's latency a function of
     * WHICH record matched. Names are unique (add replaces), so the first
     * match is the record. */
    for (size_t i = 0; i < store->n; i++) {
        if (match == (size_t)-1 &&
            name_eq(store->rec[i].name, name) != 0) {
            match = i;
        }
    }
    /* The offered password is derived ONCE: under the matched record's salt
     * and iteration count -- old records keep verifying under the count they
     * were stretched with -- or under the dummy salt when nothing matched, so
     * a miss pays the same KDF a hit pays. Every comparison below is
     * hash-against-hash. */
    if (match != (size_t)-1) {
        account_hash_password(store->rec[match].salt, store->rec[match].iter,
                              password, want);
    } else {
        account_hash_password(dummy_salt, ACCOUNT_PBKDF2_ITER, password, want);
    }
    if (match != (size_t)-1) {
        saw_match |= (unsigned)secret_const_time_eq(store->rec[match].phash,
                                                    want, ACCOUNT_HASH_LEN);
    }
    /* A miss still pays one comparison, so an account that is not in the registry
     * is not distinguishable by timing from one whose password is wrong. The
     * compare runs UNCONDITIONALLY -- a hit must cost the same as a miss, so
     * the guard that skipped it on a hit is gone and the result stays ignored. */
    dummy_used =
        (unsigned)secret_const_time_eq(dummy_hash, want, ACCOUNT_HASH_LEN);
    (void)dummy_used;
    account_wipe(want, sizeof want);
    return (int)(saw_match & 1u);
}

/* 1 when no byte run in the registry's records still equals `password` -- i.e.
 * the heap holds the salted hash and not the literal. A test cannot read the
 * layout (the type is opaque), so this is the predicate that says it. 0 on a
 * NULL registry or an empty password, which is the fail-closed answer for a
 * predicate whose whole job is to refuse. */
int account_store_holds_no_plaintext(const account_store_t *store,
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

/* One record per line: `name TAB password TAB created` (legacy: re-salted and
 * stretched on the way in), or `name TAB $pbkdf2-sha256$... TAB created` (the
 * format account_store_format_record() writes). Returns 0 on success, -1
 * on anything else. The line is modified in place, so the caller hands it a
 * buffer it owns -- the same arrangement sasl_framework.c's store_parse_line()
 * uses, and for the same reason: it is on a load path that runs once per process
 * and there is nothing to be gained by allocating. */
static int store_parse_line(account_store_t *store, char *line)
{
    char *tab1;
    char *tab2;
    char *value;
    long created = 0;

    tab1 = strchr(line, '\t');
    if (tab1 == NULL) {
        return -1;
    }
    *tab1 = '\0';
    tab2 = strchr(tab1 + 1, '\t');
    if (tab2 == NULL) {
        return -1;
    }
    *tab2 = '\0';
    value = tab2 + 1;
    /* Trailing CR/LF, because a file written on a machine whose newline is CRLF
     * is an operator's file and not a broken one. Anything else in the
     * timestamp is a refusal -- parse_created() requires digits to the end. */
    {
        size_t vlen = strlen(value);

        while (vlen > 0u &&
               (value[vlen - 1u] == '\r' || value[vlen - 1u] == '\n')) {
            value[--vlen] = '\0';
        }
    }
    if (line[0] == '\0') {
        return -1; /* "TAB password TAB created": a record with no name */
    }
    if (parse_created(value, &created) != 0) {
        return -1;
    }
    /* A FOURTH field is a file written by something that does not mean what
     * this module means. Guessing which three of four are the ones is how a
     * password ends up in a timestamp column, so it is refused. */
    if (strncmp(tab1 + 1, ACCOUNT_HASH_MAGIC, sizeof ACCOUNT_HASH_MAGIC - 1u) == 0) {
        return store_parse_hashed(store, line, tab1 + 1, created);
    }
    return account_store_add(store, line, tab1 + 1, created);
}

account_store_t *account_store_load(const char *path)
{
    FILE *f;
    secret_open_status_t open_status = SECRET_OPEN_FAIL_OPEN;
    unsigned open_mode = 0u;
    account_store_t *store;
    char line[ACCOUNT_MAX_LINE];

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    /* OPEN FIRST, THEN fstat THE DESCRIPTOR: one shared open
     * (see secret_file_open in core/secret_util.h) whose refusal reasons are
     * the ones below. */
    f = secret_file_open(path, &open_status, &open_mode);
    if (f == NULL) {
        if (open_status == SECRET_OPEN_FAIL_FSTAT) {
            printf("[observable] account_store: state=REFUSED path=%s reason=fstat\n",
                   path);
        } else if (open_status == SECRET_OPEN_NOT_REGULAR) {
            printf("[observable] account_store: state=REFUSED path=%s "
                   "reason=not_regular\n",
                   path);
        } else if (open_status == SECRET_OPEN_BAD_MODE) {
            printf("[observable] account_store: state=REFUSED path=%s reason=mode_%03o "
                   "(group or other may access a file of passwords)\n",
                   path, open_mode);
        } else {
            printf("[observable] account_store: state=REFUSED path=%s reason=open\n",
                   path);
        }
        return NULL;
    }

    store = account_store_new();
    if (store == NULL) {
        (void)fclose(f);
        return NULL;
    }
    while (fgets(line, (int)sizeof line, f) != NULL) {
        const size_t n = strlen(line);
        char *p = line;

        /* A full buffer with no terminator is over-long, even at EOF:
         * fgets only returns short on newline or EOF, so a full buffer
         * means the line did not fit, trailing newline or not. */
        if (n == sizeof line - 1u && line[n - 1u] != '\n') {
            printf("[observable] account_store: state=REFUSED path=%s "
                   "reason=line_too_long\n",
                   path);
            account_wipe(line, sizeof line);
            account_store_free(store);
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
            printf("[observable] account_store: state=REFUSED path=%s "
                   "reason=malformed_record\n",
                   path);
            account_wipe(line, sizeof line);
            account_store_free(store);
            (void)fclose(f);
            return NULL;
        }
    }
    if (ferror(f) != 0) {
        printf("[observable] account_store: state=REFUSED path=%s "
               "reason=read_error\n",
               path);
        account_wipe(line, sizeof line);
        account_store_free(store);
        (void)fclose(f);
        return NULL;
    }
    /* The line buffer held plaintext passwords; the heap holds only hashes. */
    account_wipe(line, sizeof line);
    (void)fclose(f);

    if (store->n == 0u) {
        /* A registry with no records holds no accounts, and reporting it as
         * loaded would make this node answer questions about accounts it does
         * not have -- the exact thing "advertise only what you have" exists to
         * prevent, applied to a table rather than to a capability. */
        printf("[observable] account_store: state=REFUSED path=%s "
               "reason=no_records\n",
               path);
        account_store_free(store);
        return NULL;
    }
    printf("[observable] account_store: state=LOADED path=%s records=%zu\n", path,
           store->n);
    return store;
}
