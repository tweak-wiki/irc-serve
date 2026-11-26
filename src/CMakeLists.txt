# CMake for src
#
#   sasl_framework.c is here because it was NOT, and that was the defect (#86): it
#   was compiled as a source of the test_sasl_handshake executable from
#   tests/compliance/CMakeLists.txt, so SASL was absent from the shipped library
#   entirely -- a Phase-8 feature with no place in irc_core to grow into. It is
#   still the Phase-8 placeholder implementation (see docs/SERVER_DESIGN.md and
#   #82), and being in the library now means the code that replaces it has a target
#   to live in and a header (src/sasl_framework.h) that is on the include path for
#   everything linking irc_core, rather than a test-local extern declaration.

# ---------------------------------------------------------------------------
# WITH_TLS: THE OPTIONAL THIRD-PARTY DEPENDENCY (Phase 12)
# ---------------------------------------------------------------------------
# OFF BY DEFAULT, and the reason is in README.md's own claim. This project had no
# third-party dependencies for eleven phases and said so in three places; making
# OpenSSL mandatory would falsify all three AND make every CI runner grow a
# package step -- which is how a runner that cannot install it fails, in a build
# log rather than as a decision.
#
# WHAT "OPTIONAL" BUYS, concretely:
#   - the default build compiles ZERO tokens of OpenSSL and links nothing beyond
#     libc and pthread, which is what makes "no REQUIRED dependencies" true
#     rather than aspirational;
#   - the regression suite runs against the default build, so "plaintext is
#     byte-identical" is a claim about the configuration this project ships;
#   - a deployment that does not want TLS does not link a TLS stack.
#
# WHAT IT COSTS, and this is the honest half: a node built with the default
# options cannot upgrade any connection. There is no `sts` capability, no `tls`
# capability, and STARTTLS is answered 691. The startup line says so.
#
# WHY find_package(OpenSSL) RATHER THAN A HAND-ROLLED -lssl -lcrypto: pkg-config
# on this machine reports an include path inside a versioned Homebrew Cellar
# directory, so a hand-rolled one would make the DEFAULT build depend on a
# Homebrew layout -- exactly the dependency this option exists to keep out. The
# find module is also what puts the OpenSSL headers on the SYSTEM include path,
# which is what lets -Weverything's -Wsystem-headers stop firing on them (see the
# -Wno- third-party scoping in the top-level CMakeLists.txt).
#
# IT IS DECLARED HERE, ABOVE add_library(), because the two backend source files
# are selected with a generator expression that reads WITH_TLS -- and a generator
# expression is evaluated at generate time, so an option defined after
# add_library() is undefined to it and $<NOT:${WITH_TLS}> expands to nothing.
option(WITH_TLS "Build the optional OpenSSL TLS layer (adds a third-party dependency)" OFF)
if(WITH_TLS)
  find_package(OpenSSL 1.1.1 REQUIRED)
endif()

# ---------------------------------------------------------------------------
# -Wno-cast-function-type-strict, SCOPED TO ONE FILE, FOR ONE THIRD-PARTY MACRO
# ---------------------------------------------------------------------------
# The OpenSSL backend has to register a certificate-status callback on its ACCEPT
# context -- without it OpenSSL does not even READ a client's `status_request`
# extension, so a node cannot staple anything (src/tls_openssl.c's tls_status_cb()
# quotes the source). The macro that registers it is
#
#   #define SSL_CTX_set_tlsext_status_cb(ssl, cb)                     \
#       SSL_CTX_callback_ctrl(ssl, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, \
#           (void (*)(void))cb)
#
# and the cast on the last line is the diagnostic's source: an
# `int (*)(SSL *, void *)` callback becomes a `void (*)(void)`, which is exactly
# what -Wcast-function-type-strict exists to report. It is reported AT THIS FILE
# rather than inside the header, because the macro expands here.
#
# EVERY SPELLING WARNS. Measured on clang 23 and Apple clang 21, against OpenSSL
# 4.0.3: the macro directly; the underlying SSL_CTX_callback_ctrl() with the same
# cast written out; and through a typedef so the cast is an implicit conversion.
# The warning set is not the problem and the code is not the problem, so the only
# three moves are obey, suppress globally, or suppress here.
#
# WHY HERE AND NOT GLOBALLY, which is the rule the top-level CMakeLists states for
# exactly this situation: scope the THIRD-PARTY warning rather than narrow the
# PROJECT's own set. A global -Wno-cast-function-type-strict would stop reporting a
# real function-pointer mismatch in this project's 42,000 lines, permanently and
# invisibly, to accommodate one macro in one file. Scoped to tls_openssl.c the cost
# is bounded to the file that talks to OpenSSL, and that cost is stated rather than
# assumed: a function-pointer cast in tls_openssl.c itself would now go unreported.
# It is the smaller loss, and it is a loss.
#
# VERSION-GUARDED, because the diagnostic was added in Clang 16 and an unknown
# -Wno- on an older driver is -Wunknown-warning-option, which -Werror turns into a
# hard build failure -- so a suppression intended to keep the build green would
# instead turn it red. Clang 15 and older simply do not have the diagnostic to
# suppress. GCC does not have it at all, which is why the guard is Clang-only: the
# gcc-16 sanitizer cell compiles this file with no suppression of any kind.
if(WITH_TLS)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
      set_source_files_properties(tls_openssl.c PROPERTIES
        COMPILE_OPTIONS "-Wno-cast-function-type-strict")
    endif()
  endif()
endif()

add_library(irc_core STATIC
  ircv3_tags.c
  sasl_framework.c
  # Phase 12: the TLS BACKEND, and why it is two mutually exclusive files rather
  # than one #ifdef. `WITH_TLS` selects between them at configure time, so a
  # no-TLS build does not contain a single token of OpenSSL and a TLS build does
  # not contain the stub. The header both of them implement is src/tls_backend.h,
  # and it is the ONLY place the rest of the tree names TLS at all -- see its
  # comment for why that file has one function in it.
  #
  # IT IS NOT A LINK-TIME OPTION. OpenSSL could have been a find_package() with a
  # stub for the not-found case, but that makes a typo in a build directory's
  # cache decide whether a node is encrypted, silently. An explicit -DWITH_TLS=ON
  # is a thing an operator has to write down, and it is what the README will say.
  $<$<BOOL:${WITH_TLS}>:tls_openssl.c>
  $<$<NOT:$<BOOL:${WITH_TLS}>>:tls_none.c>
  # Phase 12: the TRANSPORT. Compiled in EVERY configuration, because plaintext is
  # not "TLS with the crypto stubbed out" -- it is the implementation this project
  # shipped for eleven phases, and the zero-dependency build is the one the
  # regression suite runs against. transport.h has the interface and the argument
  # for why it is three functions wide.
  core/transport.c
  # Phase 10.1: the ACCOUNT REGISTRY. It sits beside sasl_framework.c and NOT
  # inside core/ for the same reason sasl_framework.c is at this level: it is a
  # file-backed secret store whose layout and bounds belong to one module, and
  # both that module and the credential store it is deliberately separate from
  # are loaded from main() before the loop is armed. See account_store.h for the
  # argument that they are two files rather than one.
  account_store.c
  core/secret_util.c
  core/message.c
  core/connection.c
  # #543 TU-44: server.c is fully split (last family: lifecycle + clock/
  # tick/msg-id -> core/server_lifecycle.c); this file now holds only the
  # split map and is no longer compiled.
  # #543: the nick/channel string -> pointer map split out of server.c.
  # The registries that use it stay there; this file holds the table.
  core/strtab.c
  # #543: the writer pool (demand-steal drain threads) split out of server.c.
  # The lifecycle, registries and shutdown stay there; this file holds the pool.
  core/server_writers.c
  # #543: the fd-indexed connection registry (accept/lookup/queue/reap) split
  # out of server.c. The lifecycle, nick/channel registries and shutdown stay
  # there; this file holds the registry.
  core/server_conns.c
  # #543: the nick, channel and peer-link registries (claim/release/lookup/
  # enumeration, attach/get/detach, find_link/link_at/find_peer) split out of
  # server.c. The lifecycle, dial registry and shutdown stay there; this file
  # holds the registries.
  core/server_registry.c
  # #543: the nonblocking outbound-dial FSM (dial/collect/progress/count) split
  # out of server.c. The lifecycle and shutdown stay there; this
  # file holds the dial side of 3.4.
  core/server_dial.c
  # #543: the listener arms (listen/port/listen_tls/accept_tls_one) split
  # out of server.c. The lifecycle and shutdown stay there; this
  # file holds the bind side of 3.4.
  core/server_listen.c
  # #543: the shutdown trio (phase1 goodbye/phase2 close/shutdown) split
  # out of server.c. The lifecycle, clock, tick and msg-id counter live in
  # core/server_lifecycle.c now; this file holds the teardown.
  core/server_shutdown.c
  # #543: the lifecycle (server_init plus the msgid seed helpers), the clock
  # (server_now_ms), the tick (server_tick) and the msg-id counter
  # (server_next_msg_id) split out of server.c. All four stay declared in
  # core/server.h; this file holds the final family.
  core/server_lifecycle.c
  core/channel.c
  core/poll_loop.c
  core/reply.c
  core/resume.c
  # #543 TU-47: fanout.c is fully split (last family: 3.2 cap + emission stamp
  # -> fanout_cap.c) and holds only the split map, so it is no longer compiled.
  # #543: the resolution family (mask match, nick lookup, target resolve,
  # membership) split out of fanout.c; this file holds the "what did this name
  # refer to" half.
  core/fanout_resolve.c
  # #543: the forward leg (target-set walk + the fanout_forward_* entry
  # points) split out of fanout.c; this file holds the forward half and the
  # two static helpers it owns.
  core/fanout_forward.c
  # #543: the delivery leg (emission helpers, write_to_members, the
  # fanout_deliver_* entry points) split out of fanout.c; this file holds the
  # delivery half and the static helpers it owns.
  core/fanout_deliver.c
  # #543: the 3.2 client-facing cap (fanout_line_fits_n()/fanout_line_fits())
  # and the shared emission identity (fanout_stamp()) split out of fanout.c.
  # All three stay declared in core/fanout.h; this file holds the final family.
  core/fanout_cap.c
  # #543 TU-37: commands.c is fully split (last family -> commands_state.c)
  # and holds only the split map, so it is no longer compiled.
  # #543: the dispatch seam (command table + lookup + commands_dispatch())
  # split out of commands.c, with handle_motd() moving to commands_welcome.c.
  # Declared in core/commands_dispatch.h, re-exported through core/commands.h.
  core/commands_dispatch.c
  # #543: the AUTHENTICATE family (SASL PLAIN exchange) split out of commands.c.
  # The dispatch table in commands_dispatch.c names it; this file holds the handler.
  core/commands_auth.c
  # #543: the account-registration family (REGISTER/ACCOUNT/UNREGISTER refusal
  # policy) split out of commands.c. The dispatch table in commands_dispatch.c
  # names them; this file holds the handlers and their helper.
  core/commands_account.c
  # #543: the server-info family (LUSERS/ADMIN/INFO) split out of commands.c.
  # The table in commands_dispatch.c names them; this file holds the verbs.
  core/commands_info.c
  # #543: the registration family (PASS/NICK/USER) split out of commands.c.
  # The table in commands_dispatch.c names them; this file holds the handlers.
  core/commands_register.c
  # #543: the connection-lifecycle handlers (PING/PONG/QUIT) split out of
  # commands.c. The table in commands_dispatch.c names them; this file holds the handlers.
  core/commands_conn.c
  # #543: the SETNAME family (IRCv3 `setname`) split out of commands.c.
  # The table in commands_dispatch.c names it; this file holds the handler.
  core/commands_setname.c
  # #543: the CHOPER refusal family (RFC 2812 3.4.1) split out of commands.c.
  # The table in commands_dispatch.c names it; this file holds the handler.
  core/commands_choper.c
  # #543: the STARTTLS family (upgrade refusals + CAP pass-through) split out
  # of commands.c. The table in commands_dispatch.c names them; this file holds the handlers.
  core/commands_starttls.c
  # #543: the welcome burst (001-005 + MOTD) split out of commands.c, with
  # handle_motd() moving here for the table in commands_dispatch.c.
  # commands_state_update() lives in commands_state.c and calls in.
  core/commands_welcome.c
  # #543: the registration projection (commands_registered() and
  # commands_state_update()) split out of commands.c, completing it.
  # Declared in core/commands_state.h, re-exported through core/commands.h.
  core/commands_state.c
  # Phase 10.1: the account IDENTITY on a connection. It is a module of its own
  # for the reason core/cap.c is -- the predicate every consumer asks must have
  # one home, or two callers will each write `c->logged_in && c->account[0]` and
  # the pair will be read apart somewhere.
  core/account.c
  # Phase 8: the IRCv3 capability negotiation. It is a module of its own rather
  # than part of commands.c because the TABLE of what this node implements is
  # the part that has to be read in one place -- a capability advertised by a
  # literal at a call site is a claim with no owner.
  core/cap.c
  # #543 TU-54: 4.1's JOIN (handle_join() + chan_admit() + shared helpers;
  # the last family out of core/chan_verbs.c, which is now a split-map
  # pointer file only and is no longer compiled). Declared in
  # core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_join.c
  # #543 TU-45: 4.2's KNOCK (handle_knock()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_knock.c
  # #543 TU-46: 4.1's LIST (handle_list()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_list.c
  # #543 TU-48: 4.2's INVITE (handle_invite() + notify_invite()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_invite.c
  # #543 TU-49: 4.1's PART (handle_part()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_part.c
  # #543 TU-50: 4.1's TOPIC (handle_topic()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_topic.c
  # #543 TU-51: 4.1's NAMES (handle_names()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_names.c
  # #543 TU-52: 4.1's KICK (handle_kick() + chan_remote_by_nick()) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_kick.c
  # #543 TU-53: 4.1's MODE (handle_mode() + mode_refusal/ban helpers) split out of core/chan_verbs.c.
  # Declared in core/chan_verbs.h; reached through it by commands_dispatch.c.
  core/chan_verbs_mode.c
  core/msg_verbs.c
  # Phase 10.12: IRCv3 `batch`, the client-facing half -- the BATCH verb and the
  # `@`/`+` reference tags. It is a module of its own for the reason cap.c is: the
  # per-connection batch state is read in THREE places that must agree
  # (commands.c's dispatch, reply.c's single queueing site, and the verb table),
  # and a decision any two of them have to reach into separately is a decision they
  # will eventually disagree about.
  core/batch.c
  # Phase 10.13: IRCv3 `labeled-response`. It is a module of its own because the
  # specification's requirement is not "echo the tag" but "the tag appears in EXACTLY ONE
  # LOGICAL MESSAGE", and on this node a response is frequently several lines -- so the
  # state has to answer "what tag does THIS line carry" from inside reply.c's one
  # queueing site AND "what remains to be said" from inside commands.c's dispatch tail.
  core/label.c
  # Phase 6. federation/ is a DIRECTORY of its own rather than more core/*.c,
  # because the split that matters in this phase is not "core versus
  # federation" but "encode versus decode": verbs.c is the outbound half of
  # 4.3's wire and dedup.c is 2.4's loop guard, and neither is reachable from
  # the message path yet. Putting them beside core/ would imply they are part of
  # the always-on path, and a reader would expect to find them in fanout.c.
  # #543 TU-42: verbs.c is fully split (last family: fed_touch_server() +
  # fed_actor_prefix() + fed_local_emit() + fed_forward_all() -> verbs_emit.c)
  # and holds only the split map, so it is no longer compiled.
  # The shared emit helpers the decode side reports through, split out of
  # verbs.c (issue #543). Declared in federation/verbs.h.
  federation/verbs_emit.c
  # fed_obs(), the ONE printf for a peer-path log line, split out of verbs.c
  # (issue #543). Declared in federation/obs.h, re-exported via verbs.h.
  federation/obs.c
  # The frozen S-verb shapes: the per-verb parameter encoders, split out of
  # verbs.c (issue #543). Listed beside verbs.c, whose header declares them.
  federation/shapes.c
  # The outbound encode half (S_VERBS map + fed_sverb_for + fed_queue_why_name +
  # fed_queue_line + fed_send_sverb with its fed_relay_clean filter), split out of
  # verbs.c (issue #543). Listed beside verbs.c, whose header declares them.
  federation/encode.c
  # The ADVERTISE store: what a peer advertises and the collision check, split
  # out of verbs.c (issue #543). Listed beside verbs.c; the store readers stay
  # declared in federation/link.h.
  federation/advertise.c
  # The 4.3 extension's inbound notify half (SSETNAME/SAWAY/SINVITE), split
  # out of verbs.c (issue #543). Listed beside verbs.c; fed_dispatch() lives
  # in dispatch.c and reaches the handlers through federation/notify.h.
  federation/notify.c
  # The inbound membership half (SJOIN/SNICK + fed_in_channel), split out of
  # verbs.c (issue #543). Listed beside verbs.c; fed_dispatch() lives in
  # dispatch.c and reaches the handlers through federation/membership.h.
  federation/membership.c
  # The inbound channel-state and departure half (SHUTDOWN/SPART/STOPIC/
  # SMODES/SKICK/SQUIT), split out of verbs.c (issue #543). Listed beside
  # verbs.c; fed_dispatch() lives in dispatch.c and reaches the handlers
  # through federation/state.h.
  federation/state.c
  # The inbound guard chain (fed_in_message + INBOUND/DEFERRED tables +
  # fed_dispatch), split out of verbs.c (issue #543). Listed beside verbs.c;
  # the handlers stay declared in their own headers, which this module reads.
  federation/dispatch.c
  federation/dedup.c
  # #543 TU-41: link.c is fully split (last family: FED_REASON_NAME +
  # fed_federate_reason() -> link_dump.c) and holds only the split map,
  # so it is no longer compiled.
  # The tick: the dial/retry arms and fed_tick() itself, split out of link.c
  # (issue #543). Listed beside link.c; the exchange half it reaches stays
  # declared in federation/link.h.
  federation/tick.c
  # The open/close + per-node timer/retry overrides (fed_open/fed_close/
  # fed_set_timeouts/fed_hs_due/fed_set_retry, with link_wipe()), split out of
  # link.c (issue #543). Listed beside link.c; all five stay declared in
  # federation/link.h.
  federation/link_config.c
  # The handshake FSM: the caller-owned-context transition rules, split out of
  # link.c (issue #543). It is listed here, beside its only production caller,
  # because that is where a reader looking for the rules will look first.
  federation/handshake.c
  # The FEDERATE admission guard (secret_matches + fed_check_federate()),
  # split out of link.c (issue #543). Listed beside link.c; the verdict
  # stays declared in federation/link.h.
  federation/link_guard.c
  # The accept half (fed_reject + fed_link_established + fed_refuse +
  # fed_claim_accepted + fed_on_federate + fed_dispatch_hook), split out of
  # link.c (issue #543). Listed beside link.c; the seam stays declared in
  # federation/link.h.
  federation/link_accept.c
  # The observable dump (FED_REASON_KEY + fed_state_name() + fed_dump()) plus
  # the reason spellings (FED_REASON_NAME + fed_federate_reason(), TU-41),
  # split out of link.c (issue #543). Listed beside link.c; fed_dump() and
  # fed_federate_reason() stay declared in federation/link.h.
  federation/link_dump.c
  # The link table (fed_link_set_state() + fed_link_of_conn() + fed_link_new() +
  # fed_link_set_tls() + fed_link_configure()), split out of link.c
  # (issue #543). Listed beside link.c; all five stay declared in
  # federation/link.h.
  federation/link_table.c
  # The FEDERATE exchange sender (fed_queue_federate()), split out of link.c
  # (issue #543). Listed beside link.c; it stays declared in
  # federation/link.h.
  federation/link_queue.c
  # The departure half: the SQUIT announcement, the link teardown, the clean-leave
  # latch, the shutdown drain and the operator's reset door, split out of link.c
  # (issue #543). Listed beside link.c; link.c reaches fed_link_down() through
  # federation/departure.h.
  federation/departure.c
  # The resync: 4.3's SBURST, the wire format it froze, and the transaction that
  # replaces rather than merges. It is listed LAST because it is the one module
  # here that depends on both of the others -- link.c calls federation_resync()
  # at establishment and fed_burst_abandon() on link-down, and burst.c reaches the
  # guard chain's vocabulary through federation/verbs.h. A shadow is a
  # transaction the size of a channel list, which is the reason it is a file and
  # not a function in the module that decides which sockets are up.
  federation/burst.c
  # Phase 9's remote-nick registry: 2.1's "which server holds the user called
  # X", which is what makes 3.1's `nick@server` row resolvable rather than merely
  # routable, and the rename-the-loser decision that goes with it. It is listed
  # LAST because it is the only module here that depends on TWO others -- it
  # includes federation/link.h for the liveness constant its TTL is derived from,
  # and core/channel.h for valid_nick() and the remote-host width, which is a
  # wider dependency surface than anything else under federation/ has. The table
  # itself is a vector on server_t rather than a module global, so it has a home
  # the shutdown can reach -- the difference between it and the burst shadow,
  # which is a file-scope static and needs fed_burst_close() to be released.
  federation/nickreg.c
)

# Portable threads linkage: find_package(Threads) resolves to -pthread on
# glibc and to nothing extra on macOS, where pthread is in libSystem. A bare
# `pthread` library name is not portable (it is a linker search, not a target),
# and C11 threads.h stays unused -- the codebase calls pthread_* directly.
find_package(Threads REQUIRED)
target_link_libraries(irc_core PRIVATE Threads::Threads)

if(WITH_TLS)
  # PUBLIC, because a test that drives a real handshake links OpenSSL headers of
  # its own -- see tests/integration/CMakeLists.txt's TLS block.
  target_link_libraries(irc_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  # PRIVATE: the rest of the tree must not learn that TLS exists from a macro. The
  # one fact anything outside the backend needs is tls_backend_available(), and
  # tls_backend.h is the header for it.
  target_compile_definitions(irc_core PRIVATE IRC_WITH_TLS=1)
  message(STATUS "irc-serve: TLS ENABLED (${OPENSSL_VERSION}); "
                 "the zero-dependency build is OFF")
endif()

# Expose src/ headers to anything linking irc_core (tests, benchmarks).
target_include_directories(irc_core PUBLIC ${PROJECT_SOURCE_DIR}/src)

# Executable for federated node
add_executable(irc-serve node_main.c node_opts.c)
target_link_libraries(irc-serve PRIVATE irc_core)

install(TARGETS irc-serve RUNTIME DESTINATION bin)
