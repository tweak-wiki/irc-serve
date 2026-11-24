/* strtab.h -- the nick/channel string -> pointer map.
 *
 * Split out of core/server.c (#543): the two registries (nicks, channels)
 * are served by one open-addressed, linearly-probed table, and the table is
 * what this module owns. server.c holds the two table pointers and calls
 * these; nothing outside strtab.c touches the buckets. The struct stays
 * opaque here for that reason.
 *
 * irc_ascii_fold()/irc_ascii_same() are NOT declared here: their single
 * definitions moved to strtab.c with the table that folds through them, but
 * their declarations stay in core/message.h, which is where every caller
 * already finds them.
 */
#ifndef IRC_CORE_STRTAB_H
#define IRC_CORE_STRTAB_H

#include <stddef.h>
#include <stdint.h>

struct strtab;

struct strtab *strtab_new(int folded, uint64_t seed);
void strtab_free(struct strtab *t);
int strtab_contains(const struct strtab *t, const char *key);
int strtab_put(struct strtab *t, const char *key, void *val);
void *strtab_get(const struct strtab *t, const char *key);
int strtab_del(struct strtab *t, const char *key);
size_t strtab_count_owner(const struct strtab *t, const void *owner);
size_t strtab_del_owner(struct strtab *t, const void *owner);

#endif /* IRC_CORE_STRTAB_H */
