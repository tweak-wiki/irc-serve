/* commands.c -- see commands.h. The last family split out for #543 was the
 * registration projection (commands_registered() and commands_state_update())
 * into core/commands_state.c; this file now holds only the split map. The
 * welcome burst (001-005 + MOTD) lives in core/commands_welcome.c,
 * registration (PASS/NICK/USER) in core/commands_register.c, the
 * connection-lifecycle handlers (PING/PONG/QUIT) in core/commands_conn.c,
 * and the dispatch seam (the command table both a client line and a peer
 * line arrive at) in core/commands_dispatch.c.
 */

/* The registration projection: split out for #543 into
 * core/commands_state.c; declared in core/commands_state.h and re-exported
 * through core/commands.h. */

/* Node identity, and how much of it exists yet
 *
 * 005's NETWORK= and 001's wording both need a network name, and 002/004/PONG
 * need the node's own name. server_t already carries `name`, validated at
 * server_init() against the 2.4 tag grammar, so that is used directly and no
 * new field is added.
 *
 * The NETWORK name is a DEPLOYMENT property rather than a node property -- a
 * mesh has many nodes and one network name -- and a second per-server field
 * would be the first half of a server-identity system. So it is a single
 * compile-time constant (NODE_NETWORK in core/commands_info.h), and the honest
 * limitation is stated rather than papered over: a node serving more than one
 * network is not expressible in Phase 3, and Phase 6's server identity is
 * where that belongs. */

/* Welcome burst (001-005 + MOTD): split out for #543 into
 * core/commands_welcome.c; send_welcome()/send_motd() are declared in
 * core/commands_welcome.h and called by commands_state_update(). */

/* SETNAME family (IRCv3 `setname` + common-channel notify): split out for
 * #543 into core/commands_setname.c; handle_setname() is declared in
 * core/commands_setname.h and named by the table in commands_dispatch.c. */

/*
 * ---------------------------------------------------------------------------
 * EVERY LOG LINE IN THIS FILE THAT NAMES A CLIENT-SUPPLIED STRING
 * ---------------------------------------------------------------------------
 * `conn_text_logsafe()` is the one rule for all of them, and it exists because
 * there were fourteen of them and each had been written as `%s`.
 *
 * A command word, a PING token, a QUIT reason, a server mask, a nickname a client
 * offered and a SASL mechanism are all bytes off a socket, and every one of them
 * reached this node's own stdout unfiltered. The reachable ones needed no
 * credential and no registration: one unrecognised verb carrying ESC in its word,
 * one `PING`, one `QUIT`. `0x07` rings a terminal's bell and ESC `[` is a CSI
 * sequence any terminal executes, so this was a way for anyone who could open a
 * socket to rewrite an operator's screen.
 *
 * WHY NOT STRIP THESE. A STRIP is for a field that is RELAYED to other people --
 * an away message, a topic, a kick reason -- where removing the byte changes what
 * they read. Every value below is LOG-ONLY: nothing else ever sees it, so there is
 * nothing to protect by rewriting it and a great deal to lose. `cmd_unknown:
 * command=NICK` is the entire diagnostic; printed with a byte removed it would
 * name a verb the client never sent. So these are MEASURED: the value is kept when
 * every byte is printable ASCII, withheld when one is not, and the length and the
 * bad-byte count go beside it either way.
 *
 * NOT ALL FOURTEEN WERE BROKEN, and the ones that were not are named at their own
 * definitions rather than here. `commands.c` prints `c->nick`, `c->user`,
 * `c->host`, `c->realname`, `c->account` and `ch->name` throughout: every one of
 * those passed `valid_nick()`, `chan_name_valid()`, `conn_realname_check()` or
 * `account_name_wire_safe()` on the way in, and a field that cannot hold a byte
 * from the set needs no second opinion on the way out.
 * ---------------------------------------------------------------------------
 */

/* Connection-lifecycle handlers (PING/PONG/QUIT): split out for #543 into
 * core/commands_conn.c; the table in commands_dispatch.c is their only
 * caller. */

/* MOTD handler: split out for #543 into core/commands_welcome.c;
 * handle_motd() is declared in core/commands_welcome.h and named by the
 * table in commands_dispatch.c. */

/* 4.2's CHOPER, and the REFUSAL POLICY for operator commands: split out for
 * #543 into core/commands_choper.c; handle_choper() is declared in
 * core/commands_choper.h and named by the table in commands_dispatch.c. */

/* STARTTLS family (upgrade refusals + CAP pass-through): split out for
 * #543 into core/commands_starttls.c; handle_starttls() and
 * handle_cap_wrapper() are declared in core/commands_starttls.h and named
 * by the table in commands_dispatch.c. */

/* The dispatch seam (command table + lookup + commands_dispatch()): split
 * out for #543 into core/commands_dispatch.c; declared in
 * core/commands_dispatch.h and re-exported through core/commands.h. */
