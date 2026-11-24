# Deploying irc-serve

Live servers run on the CachyOS box (`cachyos-x8664`, Tailscale `100.118.147.36`)
as systemd services, deployed by the `Deploy stable + staging` workflow
(`.github/workflows/deploy.yml`) on the dedicated `tweak-deploy` runners
(`tweak-deploy-1..4`). CI builds run on the separate `tweak-ci` pool; the two
never share a runner.

## Slots

| Slot | Port | Service | Binary |
|---|---|---|---|
| Stable | 6667 | `irc-serve-stable.service` | `/opt/irc-serve/irc-serve-stable` |
| Staging | 6668 | `irc-serve-staging.service` | `/opt/irc-serve/irc-serve-staging` |

Both units are `Type=simple`, `Restart=on-failure`, enabled at boot. The unit
files are HAND-MANAGED on the box (reference copies in
`packaging/systemd/`); CI ships only the binary and runs `enable --now` /
`restart` (#532). Logs go to the journal:
`journalctl -u irc-serve-stable -n 50`.

## Procedure

0. **Install the unit files once, by hand.** Copy the reference units from
   `packaging/systemd/` to `/etc/systemd/system/` (adjust ports/names
   first), then `systemctl daemon-reload` and
   `systemctl enable --now irc-serve-staging irc-serve-stable` (plus
   `irc-serve-fed-a`/`irc-serve-fed-b` if the box runs the federated pair).
   CI never writes unit files, so this is the only write path.

1. **Deploy to staging.** Actions → `Deploy stable + staging` → Run workflow →
   `target: staging`. Test against port 6668 until happy.
2. **Promote.** Same workflow, `target: promote`. It verifies staging is up,
   installs the binary as `irc-serve-stable`, and restarts the stable service.
   `promote` (and direct `stable` deploys) target the `stable` environment,
   which requires the owner's approval before the job runs — set this up in
   repo Settings → Environments → `stable` → Required reviewers.
3. **Never deploy to stable directly** except to roll back. The promote path is
   the tested one.

## Why this shape (security)

The `tweak-deploy` runners execute `workflow_dispatch` steps. Anyone who can
trigger that workflow — or who compromises those credentials — gets arbitrary
command execution as the runner user (`powerpc`). The design question is what
that buys them.

**The runner user can run exactly five commands as root**, via
`/etc/sudoers.d/irc-serve-deploy` (installed once, by hand, on the box).
CI never writes unit files, so the `tee` rule is gone, and with it the
`daemon-reload` nothing else needs (#532):

```
powerpc ALL=(root) NOPASSWD: /usr/bin/install -d *, /usr/bin/install -m *, /usr/bin/systemctl enable --now irc-serve-*, /usr/bin/systemctl restart irc-serve-*, /usr/bin/journalctl -u irc-serve-* *
```

Everything else still requires a password. Consequences:

- A compromised workflow can restart the IRC services — annoying, but not a
  root shell, not other users' files, not package installs, not a pivot. It
  can no longer rewrite what root executes: the unit files are root-owned
  and writable only by hand on the box.
- The binary and unit files are **root-owned**: the runner user cannot silently
  swap the binary without going through a sudo call that lands in the auth log.
- The alternative considered — user-level units with no sudo — is *worse*:
  the runner user would own the binary, the units, and the linger state, so a
  workflow compromise could rewrite the "IRC server" into anything with no
  privilege boundary crossed and nothing logged.

**Closed limit (was: `tee` could write any unit content):** the `stable`
environment approval gate still stands (a human reviews before promote
touches stable) and `workflow_dispatch` still requires write access, but
neither is load-bearing for this anymore — there is no CI path that writes a
unit file.

**Reproducing this on a fresh box:** create the `powerpc` user, register four
runners with the `tweak-deploy` label (see `scripts/setup-self-hosted-runner.sh`
for the pattern, with a different label), install the narrowed sudoers file
above, `chmod 440` it, verify with `visudo -c`, copy the reference units from
`packaging/systemd/` to `/etc/systemd/system/`, `systemctl daemon-reload`,
and create the `stable` environment with yourself as required reviewer.
