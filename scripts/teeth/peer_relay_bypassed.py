"""FAULT: the SECOND RELAY PATH bypassing the strip.

`fed_queue_line()` is the only place a peer-bound line is built and
`fed_relay_clean()` is the only filter on it. The filter matches its row on the VERB,
so passing a verb that is in no row disables it completely -- which is the state the
peer sweep was committed RED in, and which is exactly what a second filter added at a
second site would look like from the outside: present, reviewed, and not on this path.

It goes through a wrong-name rather than removing the call so that the function stays
used and the build stays clean; a fault that does not compile proves nothing.
"""
from util import apply_fault

p = "src/federation/verbs.c"
old = """    filter_rc = fed_relay_clean(verb, params, nparams, arena, sizeof arena,
                                cleaned, &src_len, &kept_len);"""
new = """    /* FAULT: the verb no row matches, so nothing is filtered. */
    filter_rc = fed_relay_clean("SSPRIVMSG", params, nparams, arena, sizeof arena,
                                cleaned, &src_len, &kept_len);"""
apply_fault(p, old, new, "the relay filter call")
