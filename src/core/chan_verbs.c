/* chan_verbs.c -- see core/chan_verbs.h. The channel commands.
 *
 * Fully split for #543 (last family: JOIN + the shared
 * argument/authority/emission/helpers -> core/chan_verbs_join.c, TU-54);
 * this file now holds only the split map. All functions stay declared in
 * core/chan_verbs.h.
 */
#include "core/chan_verbs.h"


/* The JOIN family (handle_join() + chan_admit() + announce_join_away() +
 * refuse_join_too_many(), the shared argument/authority/emission/helpers
 * they are defined alongside, and the section headers): split out for #543
 * into core/chan_verbs_join.c; all stay declared in core/chan_verbs.h. */

/* handle_part(): split out for #543 (TU-49) into core/chan_verbs_part.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_topic(): split out for #543 (TU-50) into core/chan_verbs_topic.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_names(): split out for #543 (TU-51) into core/chan_verbs_names.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_list(): split out for #543 (TU-46) into core/chan_verbs_list.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_kick(): split out for #543 (TU-52) into core/chan_verbs_kick.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_mode(): split out for #543 (TU-53) into core/chan_verbs_mode.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_invite(): split out for #543 (TU-48) into core/chan_verbs_invite.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_knock(): split out for #543 (TU-45) into core/chan_verbs_knock.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */
