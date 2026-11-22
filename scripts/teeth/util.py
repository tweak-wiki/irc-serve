"""Shared exact-match patch helper for teeth fault scripts.

Every fault script reverts one fix in a staged copy of the tree. A renamed
comment makes the needle miss; a bare ``assert old in s`` catches total
misses but still applies when the needle matches twice (wrong site) or when
the replacement silently fails to land. This helper requires exactly one
match and verifies the result, so a fault that stopped applying fails
loudly instead of reporting a green that means nothing.
"""

import sys


def apply_fault(path, old, new, msg=None):
    """Replace exactly one occurrence of *old* with *new* in *path*.

    Exits 1 (loudly, on stderr) when the file is missing, the needle does
    not match exactly once, or the replacement did not land.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write("teeth fault: %s: %s\n" % (path, exc))
        raise SystemExit(1)
    found = text.count(old)
    if found != 1:
        sys.stderr.write(
            "teeth fault: %s: expected exactly one match for %s, found %d%s\n"
            % (path, msg or "the needle", found,
               " -- the source was reworded, so this fault has to follow it"
               if found == 0 else " -- refusing to patch an ambiguous site"))
        raise SystemExit(1)
    text = text.replace(old, new, 1)
    if old in text or new not in text:
        sys.stderr.write(
            "teeth fault: %s: replacement did not land for %s\n"
            % (path, msg or "the needle"))
        raise SystemExit(1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
