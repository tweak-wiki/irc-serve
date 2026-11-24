#!/bin/bash
# irc-health-check.sh HOST PORT [NICK] -- protocol-level post-deploy check (#531).
#
# A bare TCP connect passes for a wedged binary that still listens, so this
# registers a nick, expects 001, round-trips PING/PONG with a fresh token,
# then quits. Anything else fails. Deploy jobs check out the repo to run it.
set -euo pipefail

host="${1:?usage: $0 HOST PORT [NICK]}"
port="${2:?usage: $0 HOST PORT [NICK]}"
nick="${3:-deploycheck}-$$"
token="health-$$-$RANDOM"
deadline=$((SECONDS + 25))

fail() { echo "irc-health-check: $*" >&2; exit 1; }

exec 3<>"/dev/tcp/$host/$port" || fail "cannot connect to $host:$port"
trap 'exec 3<&- 2>/dev/null || true; exec 3>&- 2>/dev/null || true' EXIT

printf 'NICK %s\r\nUSER %s 0 * :deploy health check\r\n' "$nick" "$nick" >&3

# Wait for 001, answering any server PING on the way (registration probes).
got001=0
while ((SECONDS < deadline)); do
    if IFS= read -r -t 5 -u 3 line; then
        line=${line%$'\r'}
        case $line in
            *' 001 '*) got001=1; break ;;
            PING*) printf 'PONG %s\r\n' "${line#PING }" >&3 ;;
        esac
    fi
done
((got001)) || fail "no 001 for $nick"

# Liveness round-trip with a token only this run knows.
printf 'PING %s\r\n' "$token" >&3
while ((SECONDS < deadline)); do
    if IFS= read -r -t 5 -u 3 line; then
        line=${line%$'\r'}
        case $line in
            PING*) printf 'PONG %s\r\n' "${line#PING }" >&3 ;;
            *PONG*"$token"*) break ;;
        esac
    else
        fail "no PONG for token $token"
    fi
done

printf 'QUIT :health check\r\n' >&3
echo "irc-health-check: $host:$port registered $nick, 001 seen, PING/PONG ok"
