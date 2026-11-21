/* secret_util.c -- the shared secret-file open and constant-time compare.
 * See secret_util.h for why this is a file of its own. */
#include "core/secret_util.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif

FILE *secret_file_open(const char *path, secret_open_status_t *status,
                       unsigned *mode_out)
{
    struct stat sb;
    int fd;
    FILE *f;

    if (status != NULL) {
        *status = SECRET_OPEN_FAIL_OPEN;
    }
    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    /* OPEN FIRST, THEN fstat THE DESCRIPTOR.
     *
     * stat()-then-open leaves a window in which the file judged is not the
     * file read, on a file whose whole content is passwords; fstat() on the
     * descriptor cannot race, because the descriptor names an inode the kernel
     * has already opened. O_NOFOLLOW makes a symlink at the final component a
     * hard open error rather than something to reason about, and O_NONBLOCK
     * keeps a FIFO at the path from wedging the loader: the S_ISREG check
     * below refuses it instead. Nothing changes for an honest operator: same
     * refusal reasons, same mode rule. Only the order changed, and the order
     * was the bug. */
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return NULL;
    }
    if (fstat(fd, &sb) != 0) {
        if (status != NULL) {
            *status = SECRET_OPEN_FAIL_FSTAT;
        }
        (void)close(fd);
        return NULL;
    }
    if (!S_ISREG(sb.st_mode)) {
        if (status != NULL) {
            *status = SECRET_OPEN_NOT_REGULAR;
        }
        (void)close(fd);
        return NULL;
    }
    if ((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (status != NULL) {
            *status = SECRET_OPEN_BAD_MODE;
        }
        if (mode_out != NULL) {
            *mode_out = (unsigned)(sb.st_mode & 0777);
        }
        (void)close(fd);
        return NULL;
    }
    /* Regular files ignore O_NONBLOCK on read, so there is nothing to clear. */
    f = fdopen(fd, "r");
    if (f == NULL) {
        (void)close(fd);
        return NULL;
    }
    if (status != NULL) {
        *status = SECRET_OPEN_OK;
    }
    return f;
}

/* `diff` accumulates the XOR of every byte, so a mismatch anywhere makes it
 * non-zero, and the loop cannot exit early -- it always walks the whole
 * length. The accumulator is unsigned so the compiler cannot reason about its
 * value being always zero, and the result is folded to 0/1 at the end so no
 * caller can be tempted to branch on an intermediate. */
int secret_const_time_eq(const unsigned char *a, const unsigned char *b,
                         size_t n)
{
    unsigned diff = 0u;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned)(a[i] ^ b[i]);
    }
    return (diff == 0u) ? 1 : 0;
}

/* --------------------------------------------------------------------------
 * SHA-256 and the salted-hash helpers both secret stores share
 * ------------------------------------------------------------------------ */

static uint32_t secret_rotr(uint32_t x, unsigned n)
{
    return (uint32_t)((x >> n) | (x << (32u - n)));
}

static void secret_block(uint32_t h[8], const unsigned char *p)
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
        const uint32_t s0 = secret_rotr(w[i - 15u], 7u) ^
                            secret_rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        const uint32_t s1 = secret_rotr(w[i - 2u], 17u) ^
                            secret_rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);

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
            secret_rotr(e, 6u) ^ secret_rotr(e, 11u) ^ secret_rotr(e, 25u);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = hh + s1 + ch + k[i] + w[i];
        const uint32_t s0 =
            secret_rotr(a, 2u) ^ secret_rotr(a, 13u) ^ secret_rotr(a, 22u);
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

void secret_sha256_init(secret_sha256_t *ctx)
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

void secret_sha256_update(secret_sha256_t *ctx,
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
            secret_block(ctx->h, ctx->block);
            ctx->used = 0u;
        }
    }
}

void secret_sha256_final(secret_sha256_t *ctx,
                         unsigned char out[SECRET_HASH_LEN])
{
    const uint64_t bits = ctx->total * 8u;

    /* 0x80, then zeros until eight bytes remain in the block; when the block
     * fills mid-padding update() flushes it and the count resumes at zero, so
     * this terminates at 56 from either side. The eight length bytes then land
     * exactly. */
    {
        const unsigned char one = 0x80u;
        const unsigned char zero = 0u;

        secret_sha256_update(ctx, &one, 1u);
        while (ctx->used != 56u) {
            secret_sha256_update(ctx, &zero, 1u);
        }
    }
    for (size_t i = 0; i < 8u; i++) {
        const unsigned char b =
            (unsigned char)((bits >> (56u - i * 8u)) & 0xffu);

        secret_sha256_update(ctx, &b, 1u);
    }
    for (size_t i = 0; i < 8u; i++) {
        out[i * 4u] = (unsigned char)((ctx->h[i] >> 24u) & 0xffu);
        out[i * 4u + 1u] = (unsigned char)((ctx->h[i] >> 16u) & 0xffu);
        out[i * 4u + 2u] = (unsigned char)((ctx->h[i] >> 8u) & 0xffu);
        out[i * 4u + 3u] = (unsigned char)(ctx->h[i] & 0xffu);
    }
}

void secret_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;

    for (size_t i = 0; i < n; i++) {
        v[i] = 0u;
    }
}

void secret_gen_salt(unsigned char salt[SECRET_SALT_LEN])
{
#if defined(__APPLE__)
    if (getentropy(salt, SECRET_SALT_LEN) == 0) {
        return;
    }
    /* getentropy() cannot fail for 16 bytes short of a broken libc, but the
     * salt decides whether two boots' hashes can be told apart, so the
     * fallback is the call that cannot fail rather than a zeroed salt. */
    arc4random_buf(salt, SECRET_SALT_LEN);
#else
    if (getentropy(salt, SECRET_SALT_LEN) == 0) {
        return;
    }
    {
        FILE *f = fopen("/dev/urandom", "re");

        if (f != NULL) {
            const size_t got = fread(salt, 1u, SECRET_SALT_LEN, f);

            (void)fclose(f);
            if (got == SECRET_SALT_LEN) {
                return;
            }
        }
    }
    /* Last resort: no kernel RNG and no urandom device. Time, pid and a stack
     * address vary per boot; hashed, they are a unique salt, and uniqueness
     * (not secrecy) is all a per-boot salt needs. */
    {
        char mix[96];
        secret_sha256_t ctx;
        unsigned char digest[SECRET_HASH_LEN];
        int n = snprintf(mix, sizeof mix, "%llu-%ld-%p",
                         (unsigned long long)time(NULL), (long)getpid(),
                         (void *)mix);

        if (n < 0) {
            mix[0] = '\0';
        }
        secret_sha256_init(&ctx);
        secret_sha256_update(&ctx, (const unsigned char *)mix, strlen(mix));
        secret_sha256_final(&ctx, digest);
        memcpy(salt, digest, SECRET_SALT_LEN);
        secret_wipe(&ctx, sizeof ctx);
        secret_wipe(digest, sizeof digest);
        secret_wipe(mix, sizeof mix);
    }
#endif
}

void secret_hash_password(const unsigned char salt[SECRET_SALT_LEN],
                          const char *password,
                          unsigned char out[SECRET_HASH_LEN])
{
    secret_sha256_t ctx;

    secret_sha256_init(&ctx);
    secret_sha256_update(&ctx, salt, SECRET_SALT_LEN);
    secret_sha256_update(&ctx, (const unsigned char *)password,
                         strlen(password));
    secret_sha256_final(&ctx, out);
    /* The tail of the password may still sit in the context's block. */
    secret_wipe(&ctx, sizeof ctx);
}

int secret_folded_eq(const char *a, const char *b)
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
