#!/usr/bin/env bash
# Kernhaven uninstaller (M18, AT-F17-03). Removes the services, units,
# configuration and service users. Apps keep running and data stays unless
# requested.
#
#   uninstall.sh [--remove-data] [--remove-apps] [--yes]
set -euo pipefail
data=0
apps=0
yes=0
for a in "$@"; do
  case "$a" in
    --remove-data) data=1 ;;
    --remove-apps) apps=1 ;;
    --yes) yes=1 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
echo "This removes Kernhaven's services, configuration and users."
[ "$apps" = 1 ] && echo "It also REMOVES every container and volume Kernhaven created."
[ "$data" = 1 ] && echo "It also DELETES /var/lib/kernhaven (users, settings, backups' keys) and /var/lib/kernhaven-backups."
if [ "$yes" != 1 ]; then
  read -r -p "Type 'remove' to continue: " answer
  [ "$answer" = remove ] || { echo "nothing changed"; exit 1; }
fi
if [ "$apps" = 1 ] && command -v docker >/dev/null; then
  ids=$(docker ps -aq --filter label=io.kernhaven.managed=true)
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null
  fi
  vols=$(docker volume ls -q --filter label=io.kernhaven.managed=true)
  if [ -n "$vols" ]; then
    # shellcheck disable=SC2086
    docker volume rm $vols >/dev/null
  fi
fi
if [ "$data" = 1 ]; then
  install -d -m 0700 /var/lib/kernhaven-upgrade
  touch /var/lib/kernhaven-upgrade/remove-data-on-purge
fi
DEBIAN_FRONTEND=noninteractive apt-get purge -y kernhaven
echo "Kernhaven was removed."
