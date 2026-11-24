/* secret_util.h -- the one shared home for the secret stores: secret-file
 * open, constant-time digest compare, SHA-256, salt generation and the
 * ASCII-folded name compare. One copy rather than two, so the stores cannot
 * drift apart.
 *
 * WHY A FILE OF ITS OWN rather than living in sasl_framework.c: that file is
 * on test_close_sites.c's never-close list, and this open owns a descriptor
 * it must close on every failure path. An exception there would weaken the
 * audit for a file that otherwise never touches close(); a neutral home costs
 * one module and keeps the audit exact. */
#ifndef IRC_SECRET_UTIL_H
#define IRC_SECRET_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    SECRET_OPEN_OK = 0,
    SECRET_OPEN_FAIL_OPEN,
    SECRET_OPEN_FAIL_FSTAT,
    SECRET_OPEN_NOT_REGULAR,
    SECRET_OPEN_BAD_MODE
} secret_open_status_t;

/* Open `path` as a secret file: open() first with O_NOFOLLOW|O_CLOEXEC, then
 * fstat() the descriptor, requiring S_ISREG and clear group/world bits.
 * Returns the stream on success, NULL on any failure, reporting the reason in
 * `status` (and the offending mode in `mode_out` for BAD_MODE) so the CALLER
 * can print its own [observable] line -- which is what keeps each loader's
 * prefix byte-identical. NULL/empty path is silent NULL, as before. */
FILE *secret_file_open(const char *path, secret_open_status_t *status,
                       unsigned *mode_out);

/* 1 when the two fixed-length buffers hold the same bytes, in time that
 * depends only on their LENGTH and not on their contents. Both sides here are
 * digests; the comparison is hash-against-hash. */
int secret_const_time_eq(const unsigned char *a, const unsigned char *b,
                         size_t n);


/* SHA-256, bundled so the default build stays dependency-free. Both secret
 * stores (sasl_framework.c's credential store and account_store.c's registry)
 * keep salted hashes on the heap and never the passwords, and that needs a
 * hash in a build that links nothing beyond libc. One copy rather than two,
 * so a hash fix cannot land in one store and miss the other. Test vector:
 * "abc" -> ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61
 * f20015ad (checked by inspection, not by a test). */
#define SECRET_HASH_LEN 32u
#define SECRET_SALT_LEN 16u

typedef struct {
    uint32_t h[8];
    uint64_t total;
    unsigned char block[64];
    size_t used;
} secret_sha256_t;

void secret_sha256_init(secret_sha256_t *ctx);
void secret_sha256_update(secret_sha256_t *ctx, const unsigned char *data,
                          size_t len);
void secret_sha256_final(secret_sha256_t *ctx,
                         unsigned char out[SECRET_HASH_LEN]);

/* Overwrite `n` bytes at `p`, through a volatile pointer: a memset() to memory
 * about to be freed or reused is a store the compiler may prove dead and
 * delete. Shared by both stores' scrubs and by the salt fallback below. */
void secret_wipe(void *p, size_t n);

/* One salt per RECORD, drawn fresh in *_add(): two records with the same
 * password hash differently, so neither store reveals who shares a password.
 * Returns 0 when no kernel RNG is available; the caller refuses the record
 * rather than hashing under a predictable salt. */
int secret_gen_salt(unsigned char salt[SECRET_SALT_LEN]);

/* Iterated SHA-256(salt || password): one fast round is GPU-brute-forceable,
 * so the hash stretches over SECRET_HASH_ROUNDS rounds. The heap's only copy
 * of the secret is this digest; the password bytes themselves are never
 * stored. */
#define SECRET_HASH_ROUNDS 8192u
void secret_hash_password(const unsigned char salt[SECRET_SALT_LEN],
                          const char *password,
                          unsigned char out[SECRET_HASH_LEN]);

/* ASCII-folded, constant-time compare: an account name is a nickname in every
 * client that displays one, and RFC 2812 2.3.1 says nicknames compare
 * case-insensitively. A fixed walk over the longer input, no early return. */
int secret_folded_eq(const char *a, const char *b);

#endif /* IRC_SECRET_UTIL_H */
