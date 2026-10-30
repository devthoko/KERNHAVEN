#!/usr/bin/env bash
# The key pinned in packaging/get.sh must be the one in deploy/release-keys/
# (ADR-0013): one key there means get.sh pins it, none means get.sh pins
# none and refuses to install.
set -euo pipefail
cd "$(dirname "$0")/.."
pinned=$(sed -n 's/^RELEASE_PUBKEY="\(.*\)"$/\1/p' packaging/get.sh)
shopt -s nullglob
keys=(deploy/release-keys/*.pub)
if [ ${#keys[@]} -eq 0 ]; then
  [ -z "$pinned" ] || { echo "get.sh pins a key, but deploy/release-keys/ has none"; exit 1; }
  echo "no release key yet (B-3): get.sh refuses to install"
  exit 0
fi
[ ${#keys[@]} -eq 1 ] || { echo "deploy/release-keys/ must hold exactly one key for get.sh (found ${#keys[@]})"; exit 1; }
want=$(grep -v '^untrusted comment:' "${keys[0]}" | head -1 | tr -d '[:space:]')
[ "$pinned" = "$want" ] || { echo "get.sh pins a different key than ${keys[0]}"; exit 1; }
echo "get.sh pins ${keys[0]}"
