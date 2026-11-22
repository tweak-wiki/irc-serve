#!/bin/sh
# scripts/check-wired.sh -- no script in scripts/ rots unwired (#287).
#
# WHY THIS EXISTS. scripts/check-peer-log-sites.py once diverged (scanned
# printf() only, missed 56 fed_obs() sites until PR #140) because checked-in
# scripts that nothing runs rot silently. A check that matters is named in
# scripts/gate.sh, the Makefile, or .github/workflows; anything else is text.
#
# WHAT IT CHECKS. Every top-level scripts/*.py, *.sh, *.awk entry point must be
# named in one of those three surfaces, or be allowlisted below with the reason
# its indirect or human-run wiring is acceptable. A newly added script with no
# reference and no allowlist entry fails this check. scripts/teeth/* are fault
# fixtures driven by teeth.sh, not entry points, so only the top level is read.
set -eu
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/.." && pwd)

# Allowlist: named here instead of in the three surfaces, with the reason.
# strip-c-comments.awk: library sourced by scripts/check-wur-discards.sh (a CI
#   step), never run standalone.
# gen-rollback-table.py: generator run by `make docs`; its output is enforced
#   by the gated check-docs-truth.py.
# build-debian-package.sh: manual docker/Linux release recipe; its existence
#   and executability are enforced by the gated check-packaging.py.
# merge-train.sh: manual maintainer helper (needs authenticated gh);
#   documented in CONTRIBUTING.md, automatic runs nowhere by design.
# teeth.sh: manual mutation runner; its Linux counterpart teeth-linux.sh runs
#   nightly in CI.
# setup-self-hosted-runner.sh: one-off runner provisioning; documented in
#   docs/DEVELOPMENT.md, never runs in CI by design.
is_allowlisted() {
    case "$1" in
        strip-c-comments.awk|gen-rollback-table.py|build-debian-package.sh|\
        merge-train.sh|teeth.sh|setup-self-hosted-runner.sh) return 0 ;;
        *) return 1 ;;
    esac
}

fail=0
for f in "$root"/scripts/*.py "$root"/scripts/*.sh "$root"/scripts/*.awk; do
    [ -e "$f" ] || continue
    base=$(basename -- "$f")
    if is_allowlisted "$base"; then
        echo "allowlisted: $base"
        continue
    fi
    if grep -q -F -- "$base" "$root/scripts/gate.sh" "$root/Makefile" \
            "$root"/.github/workflows/*.yml 2>/dev/null; then
        echo "wired: $base"
    else
        echo "UNWIRED: $base -- add it to gate.sh, the Makefile, or workflows, or allowlist it here with a reason" >&2
        fail=1
    fi
done
if [ "$fail" -ne 0 ]; then
    echo "check-wired.sh: FAIL -- unwired scripts present" >&2
    exit 1
fi
echo "check-wired.sh: OK"
