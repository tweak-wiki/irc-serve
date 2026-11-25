"""FAULT: SMODES's allowlist removed while the CLIENT path keeps its own.

The client gate and the peer's handler both ASK `chan_mode_implemented()`. This fault
deletes the ask from the PEER'S HANDLER ONLY, so the two paths disagree again exactly
as they did before Decision C. `src/core/chan_verbs.c` and `src/core/channel.c` are
untouched, so every CLIENT test stays GREEN.

That is the whole argument for the peer sweep, and it is why this fault names only
`test_peer_terminal_sweep`: a fault invisible from the client path is not a gap in the
client tests, it is the peer path being a different path.
"""
from util import apply_fault

p = "src/federation/state.c"
old = """            verdict = chan_mode_implemented(m);
            if (verdict == 0) {"""
new = """            verdict = 1;
            if (verdict == 0) {"""
apply_fault(p, old, new, "the peer-side allowlist ask")
