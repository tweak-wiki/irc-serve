/* commands_welcome.c -- see commands_welcome.h. The welcome burst (001-005
 * then the MOTD), verbatim out of commands.c; commands_state_update() and
 * handle_motd() still live there and call in.
 */
#include "core/commands_welcome.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/channel.h"
#include "core/commands_info.h"
#include "core/reply.h"

/* 004's mode tokens. THIS NODE EVALUATES NEITHER UMODES NOR CMODES -- mode
 * handling is Phase 4 and Phase 7 -- and the tokens are advertised anyway
 * because 004's wire format has no way to express an empty mode set: a
 * non-empty string is the only thing message_format() will render in a
 * middle-parameter position. The same reasoning is why 4.4 mandates
 * PREFIX=(ov)@+ and CHANTYPES=#& that no code here acts on yet -- a client
 * that does not receive those misbehaves, and a client that offers a mode this
 * node ignores gets a visible 421 rather than silent divergence. The cost is
 * stated rather than hidden: a client may offer a mode that is not honoured,
 * and the 421 it gets back is the honest answer until that phase lands. */
#define NODE_USER_MODES "i"
#define NODE_CHAN_MODES "b,k,l,imnpst"

/* NICKLEN is derived from IRC_MAX_NICK rather than typed out, so raising the
 * struct width cannot leave 005 advertising a length the node then refuses. The
 * same argument is the reason EVERY `*LEN` token below is written this way, and
 * the reason the derivation is visible at all: an ISUPPORT length a client uses
 * to size its own buffers is a promise, and a promise that is a typed-out number
 * stops being true the moment somebody raises a bound in another file. */
#define IRC_STR_(x) #x
#define IRC_STR(x) IRC_STR_(x)

/* ---------------------------------------------------------------------------
 * 005 IS A LIST OF CLAIMS THIS NODE HONOURS, AND BOTH HALVES MATTER
 * ---------------------------------------------------------------------------
 * An ISUPPORT token is read by a client as a FACT about this server: it sizes a
 * buffer from CHANNELLEN, it decides whether a message may name six targets from
 * MAXTARGETS, it wraps a name at NAMELEN. So the list has two obligations and
 * they are opposites:
 *
 *   DERIVED, where a bound exists. Every `*LEN` and the one arity number below
 *   come from the constant that ENFORCES the thing, never from a literal. The
 *   test is not "the number looks right" but "is there a check in this tree that
 *   would refuse more than this", and a token whose answer is no is omitted.
 *   `KICKLEN` was the worked example of the second kind for two phases: Phase
 *   10.4 found that `handle_kick()` took `<reason>` verbatim with no test, so no
 *   number described the largest reason accepted AND an over-long one reached
 *   `message_format()`, which refuses rather than reshapes -- a reachable
 *   `n_reply_refused`, the counter `reply.c` holds at zero because a non-zero
 *   value is a bug report. Phase 10.9 added `CHAN_MAX_KICK_REASON`, the 417 and
 *   the token, so the worked example is now `USERLEN` below.
 *
 *   HONOURED, where a feature exists. A token a client acts on and this node does
 *   not implement is worse than the token's absence: absence is a client that
 *   carries on, presence is a client that switches the feature on and then
 *   behaves as though the server agreed. That is the same rule cap.h holds CAP LS
 *   to, applied to the other list every client reads.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT HERE, AND WHY -- the absences are the interesting half
 * ---------------------------------------------------------------------------
 * Each of these is a token a client may look for, and each is absent because
 * there is nothing behind it on this node. They are named here rather than left
 * for a reader to assume, because an absent token and a forgotten one look
 * identical on the wire.
 *
 *   BOT=B          004 advertises `i` for users and `b,k,l,imnpst` for channels,
 *                  and this node evaluates NEITHER set (commands.c's own note).
 *                  There is no BOT mode, no services, and nothing that would ever
 *                  read `BOT`. 4.3's SERVICES/bot verbs are not in 4.1 or 4.2.
 *
 *   EXTBAN=        `+b` stores a ban mask verbatim and chan_has_ban() tests it by
 *                  string equality (2.2). There is no ban EXPRESSION parser, so
 *                  there is no `~&account:name` to advertise and no `EXTBAN`
 *                  value to write. This is the same missing evaluator that
 *                  blocks IRCv3's `account-extban` (SPEC_TRACKING 10.2) -- one
 *                  gap, named twice.
 *
 *   SAFELIST       there is no safelist: `+S` is not a mode 004 advertises, and
 *                  chan_t has no safe-mask store. 2.2's ban list is a ban list.
 *
 *   MONITOR        there is no MONITOR verb. `WATCH` and `WATCHNICK` with it:
 *                  there is no WATCH verb either, so there is no watch list and
 *                  no ceiling on one.
 *
 *   MSGREFTYPES=   no message reference is recognised. `PRIVMSG @#chan :hi`
 *                  reaches fanout_resolve() with `@#chan` as the WHOLE target,
 *                  which is not a valid channel name, so it is 403 rather than a
 *                  reference to a history window. draft/message-reference is not
 *                  implemented, and this token's whole content is the list of
 *                  reference types.
 *
 *   ACCEPT         no EXCEP or INVEX mode, no accept-list storage, and no
 *                  evaluation of either. 2.2's model is one mask array for bans.
 *
 *   silence        there is no SILENCE verb and no silence store. Its absence is
 *                  a fact rather than a gap: this node has no operator concept
 *                  at all (CHOPER answers 464 for every request), and a silence
 *                  list is an operator list.
 *
 *   draft/CHATHISTORY
 *                  no channel history. resume.c's restore hands a client back the
 *                  channels it was in at disconnect, which is a SESSION and not a
 *                  history: it does not answer "what was said in #t last week"
 *                  because it does not keep anything that was not said while the
 *                  client was connected. Advertising the capability would put a
 *                  client into a state it cannot leave.
 *
 *   MODES          this token is a COUNT of mode changes permitted in one MODE
 *                  command, not a mode string (004 carries those). This node puts
 *                  no count on a MODE command, so there is no count to write.
 *
 *   USERLEN        the bound that EXISTS (CONN_USER_MAX) is not ENFORCED: USER's
 *                  ident is truncated into the field rather than refused, so
 *                  advertising a length would promise a limit this node does not
 *                  apply to the one parameter it is about. NAMELEN below is
 *                  advertised for the opposite reason: that bound IS what can be
 *                  stored, and SETNAME refuses beyond it.
 *
 * ---------------------------------------------------------------------------
 * THE `CASEMAPPING=ascii` LIE THAT IS NOT A LIE, AND WHAT rfc1459 WOULD COST
 * ---------------------------------------------------------------------------
 * Every case comparison in this tree goes through message.h's irc_ascii_fold()
 * (a-z -> A-Z, ASCII-only, locale-free), so this
 * node does NOT treat `[]\~` as equivalent to `{}|^`, which is exactly what
 * rfc1459 says it should, and advertising ascii is the truth rather than the
 * shorter answer.
 *
 * WHAT CHANGING IT WOULD COST, since the honest answer is only useful if the
 * alternative is on the record: `[]\~` and `{}\|^` become fold-equivalent, which
 * means it becomes UNSAFE to use any of those bytes in a nickname, a channel name
 * or a hostmask component -- a channel named `#a[b` and one named `#a{b` become
 * one channel. Then every comparison that folds has to fold the same way or two
 * of them disagree: server_nick_lookup(), chan_same_name(), the fanout mask
 * matcher, and the WHO mask matcher -- all through the one fold -- plus the
 * SET of bytes the validators refuse, and the validators are
 * the expensive half -- message.h's valid_nick() and chan_name_valid() would both
 * have to grow a deny-list. It is a change to what a nickname MAY BE, which is
 * why it is not something a 005 token decides. */
static const char *const k_005[] = {
    "NETWORK=" NODE_NETWORK,
    "CHANTYPES=" CHAN_TYPES, /* 4.4: many real clients misbehave without it */
    "PREFIX=(ov)@+",         /* 4.4: and without this one */
    /* True, and not a detail: message.c's up() is ASCII-only, so this node does
     * NOT treat []\~ and {}|^ as equivalent. Advertising rfc1459 here would be
     * a lie a client could act on. */
    "CASEMAPPING=ascii",
    /* ------------------------------------------------------------------------
     * THE DERIVED LENGTHS. Each one is a bound this node REFUSES to exceed, not
     * a figure of speech: raise the constant and this token moves with it.
     * ---------------------------------------------------------------------- */
    "AWAYLEN=" IRC_STR(CONN_MAX_AWAY),         /* 417, msg_verbs.c */
    "CHANNELLEN=" IRC_STR(CHAN_MAX_NAME),      /* chan_name_valid() */
    /* ADDED IN PHASE 10.9, AND IT IS THE CLOSE OF A FINDING RATHER THAN A NEW
     * TOKEN. Phase 10.4 recorded that `handle_kick()` took `<reason>` verbatim with
     * no length test, so (a) no number in the tree described the largest reason
     * this node accepts and (b) an over-long one reached `message_format()`, which
     * refuses rather than reshapes, tripping `n_reply_refused` -- the counter
     * `reply.c` holds at zero because a non-zero value is a bug report. That is a
     * reachable way to make a client command file a bug report.
     *
     * `CHAN_MAX_KICK_REASON` now enforces it and `handle_kick()` answers 417, so
     * the bound below is a fact rather than a figure of speech: it is the same
     * shape as TOPICLEN beside it, derived from the constant that refuses. */
    "KICKLEN=" IRC_STR(CHAN_MAX_KICK_REASON),  /* 417, chan_verbs.c */
    "LINELEN=" IRC_STR(IRC_MAX_LINE),          /* conn_fill() + message_parse_n() */
    "MAXTARGETS=1",                            /* MSG_MAX_TARGETS, msg_verbs.h */
    "NAMELEN=" IRC_STR(CONN_MAX_REALNAME),     /* conn_t::realname; SETNAME 417s */
    "NICKLEN=" IRC_STR(IRC_MAX_NICK),
    "TOPICLEN=" IRC_STR(CHAN_MAX_TOPIC),         /* 417, chan_verbs.c */
    /* NOTIFYLOCAL names the notifications this node emits node-local only
     * (SERVER_DESIGN 4.4.9): SETNAME/AWAY/INVITE reach local channel members
     * only until the 4.3 wire bump. Zero wire-format change: an ISUPPORT token
     * a client that does not know it ignores. */
    "NOTIFYLOCAL=SETNAME,AWAY,INVITE"
};

/* The MOTD body, sent as one 372 per line. It describes what the node IS
   * rather than what it pretends to be.
   *
   * This said "channels, messaging and federation are not implemented", false
   * from Phase 4 onward and a claim shipped to every client that connected. It
   * stayed false because a test asserted those exact bytes, and a test asserting
   * a falsehood is the usual way one survives: it looks like the thing
   * protecting the value while it is the thing keeping it wrong. The test was
   * updated with the text. INFO (371-374) is now the truthful, checkable
   * surface; the MOTD only had to stop lying. */
  static const char *const k_motd[] = {
      "- irc-serve: a federation-native IRC node.",
      "- registration, channels, messaging and peer federation are implemented.",
      "- INFO lists what this node actually does; try it."
  };

/* ---------------------------------------------------------------------------
 * 372-376: the MOTD
 * ------------------------------------------------------------------------ */

/* 003 names when this node came up, which is a fact about the boot. 3.4 says
 * handlers take their time from the tick rather than reading the wall clock,
 * and server_t::epoch cannot help: it is CLOCK_MONOTONIC milliseconds, which
 * has no calendar meaning. So this is the one deliberate wall-clock read on
 * the reply path, it is here rather than smuggled into a handler, and it is
 * read once per registration rather than once per tick. */
static void boot_stamp(char *out, size_t cap)
{
    time_t now = time(NULL);
    struct tm tm_utc;

    if (gmtime_r(&now, &tm_utc) == NULL ||
        strftime(out, cap, "%a %b %e %H:%M:%S %Y", &tm_utc) == 0) {
        (void)snprintf(out, cap, "%s", "an unknown time");
    }
}

void send_motd(server_t *s, conn_t *c)
{
    for (size_t i = 0; i < sizeof k_motd / sizeof k_motd[0]; i++) {
        (void)reply(s, c, "372", NULL, 0, "%s", k_motd[i]);
    }
    (void)reply(s, c, "375", NULL, 0, "- Message of the day -");
    (void)reply(s, c, "376", NULL, 0, "End of /MOTD command.");
}

/* 001-005 then the MOTD, in that order, in one pass over reply(). This is the
 * first thing a client sees and the first burst this node has ever produced,
 * which is why the test asserts its bytes rather than looking for "001"
 * somewhere in the stream: a malformed numeric is worse than a missing one, and
 * clients are unforgiving about the difference. */
void send_welcome(server_t *s, conn_t *c)
{
    char created[64];
    const char *modes_004[4];

    /* 001: the qualified name is <nick>!<user>@<host>, and `host` is the
     * OBSERVED peer address filled in at accept -- see handle_user(). A user
     * reading this line is being told where the node sees them from, not what
     * they typed. */
    (void)reply(s, c, "001", NULL, 0, "Welcome to the %s network %s!%s@%s",
                NODE_NETWORK, c->nick, c->user, c->host);
    (void)reply(s, c, "002", NULL, 0, "Your host is %s, running version %s",
                s->name, IRC_SERVE_VERSION);
    boot_stamp(created, sizeof created);
    (void)reply(s, c, "003", NULL, 0, "This server was created %s (UTC)",
                created);

    modes_004[0] = s->name;
    modes_004[1] = IRC_SERVE_VERSION;
    modes_004[2] = NODE_USER_MODES;
    modes_004[3] = NODE_CHAN_MODES;
    (void)reply(s, c, "004", modes_004, 4, "are supported by this server");

    (void)reply(s, c, "005", k_005, sizeof k_005 / sizeof k_005[0],
                "are supported by this server");

    printf("[observable] welcome: fd=%d nick=%s\n", c->fd, c->nick);
    send_motd(s, c);
    /* AND THE account-notify LINE, AFTER 376 AND NOT BEFORE IT.
     *
     * This is the first moment on this node at which a client can be told which
     * account it is associated with: SASL ran before registration, so before 001
     * the connection had no hostmask to attribute the line to and no nickname to
     * put in the prefix. It is after the MOTD rather than interleaved with the
     * numerics because a client parses the registration burst as one thing and an
     * extra verb in the middle of it is a line it does not expect yet.
     *
     * IT IS GATED ON THE CAPABILITY AND NOT ON WHETHER THERE IS AN ACCOUNT, which
     * is the whole of what account-notify's unconditional availability means: a
     * client that asked is told `ACCOUNT *` on a node with no registry, because
     * "you are not associated with an account" is a true and useful answer rather
     * than an absence. */
    if (cap_enabled(c, CAP_ACCOUNT_NOTIFY) != 0) {
        account_notify_current(s, c);
    }
}
