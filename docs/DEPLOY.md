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

Both units are `Type=simple`, `Restart=on-failure`, enabled at boot. Logs go
to the journal: `journalctl -u irc-serve-stable -n 50`.

## Procedure

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

**The runner user can run exactly six commands as root**, via
`/etc/sudoers.d/irc-serve-deploy` (installed once, by hand, on the box):

```
powerpc ALL=(root) NOPASSWD: /usr/bin/install -d *, /usr/bin/install -m *, /usr/bin/tee /etc/systemd/system/irc-serve-*.service, /usr/bin/systemctl daemon-reload, /usr/bin/systemctl enable --now irc-serve-*, /usr/bin/systemctl restart irc-serve-*, /usr/bin/journalctl -u irc-serve-* *
```

Everything else still requires a password. Consequences:

- A compromised workflow can restart the IRC services or rewrite their unit
  files — annoying, but not a root shell, not other users' files, not package
  installs, not a pivot.
- The binary and unit files are **root-owned**: the runner user cannot silently
  swap the binary without going through a sudo call that lands in the auth log.
- The alternative considered — user-level units with no sudo — is *worse*:
  the runner user would own the binary, the units, and the linger state, so a
  workflow compromise could rewrite the "IRC server" into anything with no
  privilege boundary crossed and nothing logged.

**Known limit:** the `tee` rule lets a deploy write *any content* to an
`irc-serve-*.service` file, and `restart` then runs it as root. That is
inherent to deploying systemd units via CI, not a flaw in the allowlist. The
mitigations are the `stable` environment approval gate (a human reviews
before promote touches stable) and the fact that `workflow_dispatch` requires
write access. A future tightening: manage the unit files by hand and deploy
only the binary — tracked, not blocking.

**Reproducing this on a fresh box:** create the `powerpc` user, register four
runners with the `tweak-deploy` label (see `scripts/setup-self-hosted-runner.sh`
for the pattern, with a different label), install the sudoers file above,
`chmod 440` it, verify with `visudo -c`, and create the `stable` environment
with yourself as required reviewer.
